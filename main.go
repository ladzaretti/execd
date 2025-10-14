package main

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"
)

var Version = "v0.0.0"

const (
	defaultUserPrefix = "/exec"
	defaultConfigName = ".execd.toml"
	defaultCacheDir   = ".execd.d"
	defaultDBFilename = "execd.sqlite"
	defaultListenAddr = ":8081"
	redact            = "*****"
)

var (
	logger   = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	config   *Config
	requests *requestStore
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

	if *configPath == "" {
		defaultPath, err := defaultConfigPath()
		if err != nil {
			logger.Error("resolve default config path", "err", err)
			os.Exit(1)
		}

		*configPath = defaultPath
	}

	c, err := loadFileConfig(*configPath)
	if err != nil {
		logger.Error("open config file", "path", *configPath, "err", err)
		os.Exit(1)
	}

	sha, err := hash(*configPath)
	if err != nil {
		logger.Error("hash config file", "path", *configPath, "err", err)
		os.Exit(1)
	}

	c.configPath = *configPath
	c.sha = sha

	logger.Info("config sha256", "sha", c.sha)

	l, _ := parseLogLevel(c.LogLevel) // already validated during config parsing

	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
	logger.Info("resolved config", "path", configPath, "config", c.redact())

	config = c

	db, err := newExecDB(c.DBPath)
	if err != nil {
		logger.Error("exec db:", "err", err)
		os.Exit(1)
	}

	requests = db
}

func hash(filename string) (string, error) {
	f, err := os.Open(path.Clean(filename))
	if err != nil {
		return "", nil
	}

	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", nil
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func chain(h http.Handler, middlewares ...func(h http.Handler) http.Handler) http.Handler {
	for _, m := range middlewares {
		h = m(h)
	}

	return h
}

func main() {
	subcommands()

	mustInitialize()

	mux, cancelableJobs := http.NewServeMux(), newSafeMap[string, func()]()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	go cancelableJobs.periodicCompact(ctx, 60*time.Minute)

	for _, e := range config.Endpoints {
		h, token := newExecHandler(ctx, e, cancelableJobs), cmp.Or(e.Token, config.Token)
		pattern := fmt.Sprintf(
			"%s %s",
			strings.ToUpper(e.method),
			e.path,
		)

		mux.Handle(pattern, chain(h,
			withAuth(token, e.NoAuth),
			withMeta,
			withCORS,
			withTracing,
		))
	}

	mux.Handle("GET /jobs/{id}", chain(newJobHandler(ctx, cancelableJobs),
		withMeta,
		withCORS,
		withTracing,
	))

	mux.Handle("GET /jobs", chain(newJobsHandler(),
		withMeta,
		withCORS,
		withTracing,
	))

	mux.Handle("GET /user-routes", chain(newRoutesHandler(config.Endpoints),
		withMeta,
		withCORS,
		withTracing,
	))

	srv := &http.Server{
		Addr:              config.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	lc := net.ListenConfig{}

	l, err := lc.Listen(ctx, "tcp", config.ListenAddr)
	if err != nil {
		logger.Error("listen failed", "addr", config.ListenAddr, "err", err)
		os.Exit(1)
	}

	logger.Info("server listening", "addr", l.Addr().String())

	errCh := make(chan error, 1)
	go func(ch chan error) {
		ch <- srv.Serve(l)

		close(ch)
	}(errCh)

	var serveErr error

	select {
	case <-ctx.Done():
		logger.Info("server signaled")

	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server terminated due to internal error", "err", err)
		}

		serveErr = err
	}

	cancel()

	_ = requests.close()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("server shutdown error", "err", err)
	}

	shutdownCancel()

	if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server exit error", "err", err)
	}

	logger.Info("server stopped")

	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		os.Exit(1)
	}
}
