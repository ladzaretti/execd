package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
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
	defaultListenAddr = ":8443"
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

	l, _ := parseLogLevel(c.Server.LogLevel) // already validated during config parsing

	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
	logger.Info("resolved config", "path", configPath, "config", c.redact())

	config = c

	reqs, err := newExecDB(c.Server.DBPath)
	if err != nil {
		logger.Error("exec db:", "err", err)
		os.Exit(1)
	}

	requests = reqs
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

func main() {
	subcommands()

	mustInitialize()

	sess := newSessions()
	rr := newRenderer()
	password := config.Server.Password

	root, cancelableJobs := http.NewServeMux(), newSafeMap[string, func()]()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	go cancelableJobs.periodicCompact(ctx, 60*time.Minute)

	// TODO: make ttl configurable, default 30m
	root.Handle("/api/", http.StripPrefix("/api", newAPIRoutes(ctx, sess, cancelableJobs, password, 30*time.Minute)))
	root.Handle("/hx/", http.StripPrefix("/hx", newHXRoutes(rr, sess, password)))
	root.Handle("/ui/", http.StripPrefix("/ui", newUIRoutes(rr, sess, password)))

	srv := &http.Server{
		Addr:              config.Server.ListenAddr,
		Handler:           root,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
	}

	lc := net.ListenConfig{}

	l, err := lc.Listen(ctx, "tcp", config.Server.ListenAddr)
	if err != nil {
		logger.Error("listen failed", "addr", config.Server.ListenAddr, "err", err)
		os.Exit(1)
	}

	logger.Info("server listening", "addr", l.Addr().String())

	errCh := make(chan error, 1)
	go func(ch chan error) {
		ch <- srv.ServeTLS(
			l,
			config.Server.CertFile,
			config.Server.KeyFile,
		)

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
