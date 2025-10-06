package main

import (
	"cmp"
	"context"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/singleflight"
)

const (
	defaultConfigName = ".exec.toml"
	defaultListenAddr = ":8081"
	redact            = "*****"
)

var (
	logger             = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	config             *Config
	allowedHTTPMethods = []string{
		http.MethodGet,
		http.MethodPost,
		http.MethodPut,
		http.MethodDelete,
		http.MethodOptions,
	}
	flightGroup singleflight.Group
)

func mustInitialize() {
	configPath := flag.String("config", "", "config file path")
	flag.Parse()

	defaultPath, err := defaultConfigPath()
	if err != nil {
		panic(err)
	}

	*configPath = cmp.Or(*configPath, defaultPath)

	c, err := loadFileConfig(*configPath)
	if err != nil {
		panic(fmt.Errorf("invalid config: %w", err))
	}

	l, err := parseLogLevel(c.LogLevel)
	if err != nil {
		panic(fmt.Errorf("invalid log level: %w", err))
	}

	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
	logger.Info("resolved config", "path", configPath, "config", c.redact())

	config = c
}

func newExecHandler(e Endpoint) http.Handler {
	method := strings.ToUpper(e.method)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Allow", method)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		v, err, _ := flightGroup.Do(e.Path, func() (any, error) {
			return e.run(r.Context())
		})
		if err != nil {
			var out []byte
			if b, ok := v.([]byte); ok {
				out = b
			}

			http.Error(w, fmt.Sprintf("exec failed: %v\n%s", err, string(out)), http.StatusInternalServerError)

			return
		}

		bs, ok := v.([]byte)
		if !ok || bs == nil {
			http.Error(w, fmt.Sprintf("exec handler: unexpected return value type %T", v), http.StatusInternalServerError)
			return
		}

		if _, werr := w.Write(bs); werr != nil {
			logger.Warn("write response failed", "err", werr, "id", requestID(r.Context()))
		}
	})
}

func withAuthMiddleware(token string, h http.Handler) http.Handler {
	const bearer = "Bearer "

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			h.ServeHTTP(w, r)
			return
		}

		auth := r.Header.Get("Authorization")
		if len(auth) < len(bearer) || !strings.EqualFold(auth[:len(bearer)], bearer) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		got, want := []byte(auth[len(bearer):]), []byte(token)
		if subtle.ConstantTimeCompare(got, want) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		h.ServeHTTP(w, r)
	})
}
func withCORS(h http.Handler) http.Handler {
	methods := strings.Join(allowedHTTPMethods, ", ")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin == "" {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		} else {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}

		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", methods)

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		h.ServeHTTP(w, r)
	})
}

type ctxKey string

var requestKey ctxKey = "requestKey"

type statusWriter struct {
	http.ResponseWriter

	status int
	n      int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}

	n, err := w.ResponseWriter.Write(b)
	w.n += n

	return n, err
}

func withTracingMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" {
			id = uuid.NewString()
		}

		ctx := context.WithValue(r.Context(), requestKey, id)

		sw := &statusWriter{ResponseWriter: w}
		sw.Header().Set("X-Request-Id", id)

		logger.Debug("request received",
			"id", id,
			"path", r.URL.Path,
			"method", r.Method,
			"remote", r.RemoteAddr,
		)

		defer func(start time.Time) {
			logger.Debug("request completed",
				"id", id,
				"status", sw.status,
				"bytes", sw.n,
				"duration", time.Since(start).String(),
			)
		}(time.Now())

		h.ServeHTTP(sw, r.WithContext(ctx))
	})
}

func requestID(ctx context.Context) string {
	v, _ := ctx.Value(requestKey).(string)
	return v
}

func main() {
	mustInitialize()

	mux := http.NewServeMux()

	for _, e := range config.Endpoints {
		h, token := newExecHandler(e), cmp.Or(e.Token, config.Token)

		h = withAuthMiddleware(token, h)
		h = withCORS(h)
		h = withTracingMiddleware(h)

		mux.Handle(e.Path, h)
	}

	srv := &http.Server{
		Addr:    config.ListenAddr,
		Handler: mux,
	}

	go func() {
		logger.Info("server listening", "addr", config.ListenAddr)

		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server error", "err", err)
		}
	}()

	ch := make(chan os.Signal, 1)
	defer close(ch)

	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)

	sig := <-ch

	logger.Info("server signaled", "signal", sig.String())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("server shutdown error", "err", err)
	}

	logger.Info("server stopped")
}
