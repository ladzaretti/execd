package main

import (
	"cmp"
	"context"
	"crypto/subtle"
	"encoding/json"
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
)

var Version = "v0.0.0"

type execState string

const (
	execStateQueued    execState = "queued"
	execStateRunning   execState = "running"
	execStateCompleted execState = "completed"
	execStateFailed    execState = "failed"
	execStateCanceled  execState = "canceled"
)

const (
	defaultConfigName = ".execd.toml"
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
)

//nolint:revive // deep-exit: a cli only helper.
func subcommands() {
	if len(os.Args) == 1 {
		return
	}

	switch os.Args[1] {
	case "version":
		if len(os.Args) > 2 {
			fmt.Fprintf(os.Stderr, "unknown command: %s\nusage: %s [version]\n", strings.Join(os.Args[1:], " "), os.Args[0])
			os.Exit(2)
		}

		fmt.Println(Version)
		os.Exit(0)
	default:
	}
}

//nolint:revive // deep-exit: allowed, mustInitialize is only called at startup
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
		logger.Error("invalid config", "err", err)
		os.Exit(1)
	}

	l, _ := parseLogLevel(c.LogLevel) //  already validated during config parsing

	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
	logger.Info("resolved config", "path", configPath, "config", c.redact())

	config = c
}

func newJobsHandler(jobs *safeMap[string, RequestState]) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "missing job id", http.StatusBadRequest)
			return
		}

		job, ok := jobs.load(id)
		if !ok {
			http.Error(w, "job not found", http.StatusNotFound)
			return
		}

		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, job)

		case http.MethodDelete:
			if job.cancel == nil {
				http.Error(w, "job not cancellable", http.StatusBadRequest)
				return
			}

			job.cancel()

			w.WriteHeader(http.StatusNoContent)

		default:
			w.Header().Set("Allow", "GET, DELETE")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

func newExecHandler(appCtx context.Context, e Endpoint, jobs *safeMap[string, RequestState]) http.Handler {
	method := strings.ToUpper(e.method)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Allow", method)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

			return
		}

		v, ok := r.Context().Value(requestKey).(string)
		if !ok {
			v = ""
		}

		id := v

		jobs.store(id, RequestState{
			State: execStateQueued,
		})

		w.Header().Set("Location", "/jobs/"+id)
		writeJSON(w, http.StatusAccepted, struct {
			ID string `json:"id,omitempty"`
		}{ID: id})

		go runRequest(appCtx, e, jobs, id)
	})
}

func runRequest(ctx context.Context, e Endpoint, jobs *safeMap[string, RequestState], id string) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs.store(id, RequestState{
		State:  execStateRunning,
		cancel: cancel,
	})

	execResult, runErr := e.run(ctx)

	completed := RequestState{
		State:  execStateCompleted,
		cancel: nil,
	}

	if execResult != nil {
		completed.Result = *execResult
	}

	if runErr != nil {
		completed.State = execStateFailed
	}

	if execResult.ExitCode != nil && *execResult.ExitCode != 0 {
		completed.State = execStateFailed
	}

	jobs.store(id, completed)

	go deleteJobAfter(ctx, jobs, id, 60*time.Minute)
}

func deleteJobAfter(ctx context.Context, jobs *safeMap[string, RequestState], id string, after time.Duration) {
	select {
	case <-time.After(after):
		jobs.delete(id)
	case <-ctx.Done():
		return
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(v); err != nil {
		logger.Warn("encode/write response failed", "err", err)
	}
}

func withAuthMiddleware(token string, unsafe bool, h http.Handler) http.Handler {
	const bearer = "Bearer "

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodOptions, unsafe:
			h.ServeHTTP(w, r)
			return
		default:
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

type RequestState struct {
	State  execState  `json:"state,omitempty"`
	Result ExecResult `json:"result"`
	cancel func()
}

func main() {
	subcommands()

	mustInitialize()

	mux, execResults := http.NewServeMux(), newSafeMap[string, RequestState]()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	go execResults.periodicCompact(ctx, 60*time.Minute)

	for _, e := range config.Endpoints {
		h, token := newExecHandler(ctx, e, execResults), cmp.Or(e.Token, config.Token)

		h = withAuthMiddleware(token, e.NoAuth, h)
		h = withCORS(h)
		h = withTracingMiddleware(h)

		mux.Handle(e.Path, h)
	}

	js := newJobsHandler(execResults)
	js = withCORS(js)
	js = withTracingMiddleware(js)

	mux.Handle("/jobs/{id}", js)

	srv := &http.Server{
		Addr:              config.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		logger.Info("server listening", "addr", config.ListenAddr)

		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server error", "err", err)
		}
	}()

	<-ctx.Done()
	cancel()

	logger.Info("server signaled")

	ctxShutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctxShutdown); err != nil {
		logger.Error("server shutdown error", "err", err)
	}

	logger.Info("server stopped")
}
