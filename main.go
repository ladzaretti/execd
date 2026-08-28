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
	"sync"
	"syscall"
	"time"
)

var Version = "v0.0.0"

const usage = `Usage:
  %s [flags]
  %s config generate
  %s version

The execd daemon exposes configured commands as authenticated HTTP endpoints.

`

const (
	defaultUserPrefix = "/exec"
	defaultConfigName = ".execd.toml"
	defaultCacheDir   = ".execd.d"
	defaultDBFilename = "execd.sqlite"
	redact            = "*****"
)

var (
	logger   = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	config   *Config
	requests *requestStore
)

func handleSubcommand(args []string, output io.Writer) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}

	switch args[0] {
	case "config":
		if len(args) != 2 || args[1] != "generate" {
			return true, fmt.Errorf("unknown command: %s\nusage: %s config generate", strings.Join(args, " "), os.Args[0])
		}

		if err := writeDefaultConfig(output); err != nil {
			return true, err
		}

		return true, nil
	case "version":
		if len(args) > 1 {
			return true, fmt.Errorf("unknown command: %s\nusage: %s [version]", strings.Join(args, " "), os.Args[0])
		}

		if _, err := fmt.Fprintln(output, Version); err != nil {
			return true, fmt.Errorf("print version: %v", err)
		}

		return true, nil
	default:
		if !strings.HasPrefix(args[0], "-") {
			return false, fmt.Errorf("unknown command: %s", strings.Join(args, " "))
		}

		return false, nil
	}
}

//revive:disable:deep-exit // This startup helper intentionally terminates the process.
func mustHandleSubcommand(args []string, output io.Writer) {
	handled, err := handleSubcommand(args, output)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	if handled {
		os.Exit(0)
	}
}

//revive:enable:deep-exit

//revive:disable:deep-exit // Startup failures must terminate the process.
func mustInitialize() {
	configPath := flag.String("config", "", "config file path (default: $XDG_CONFIG_HOME/.execd.toml; ~/.config/.execd.toml when unset)")

	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), usage, os.Args[0], os.Args[0], os.Args[0])

		flag.PrintDefaults()
	}

	flag.Parse()

	resolvedConfigPath, err := resolveConfigPath(*configPath)
	if err != nil {
		logger.Error("resolve config path", "err", err)
		os.Exit(1)
	}

	c, err := loadFileConfig(resolvedConfigPath)
	if err != nil {
		logger.Error("open config file", "path", resolvedConfigPath, "err", err)
		os.Exit(1)
	}

	sha, err := hash(resolvedConfigPath)
	if err != nil {
		logger.Error("hash config file", "path", resolvedConfigPath, "err", err)
		os.Exit(1)
	}

	c.configPath = *configPath
	c.sha = sha

	logger.Info("config sha256", "sha", c.sha)

	l, _ := parseLogLevel(c.Server.LogLevel) // already validated during config parsing

	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
	logger.Info("resolved config", "path", resolvedConfigPath, "config", c.redact())

	config = c

	reqs, err := newExecDB(c.Server.DBPath)
	if err != nil {
		logger.Error("exec db:", "err", err)
		os.Exit(1)
	}

	requests = reqs
}

//revive:enable:deep-exit

func hash(filename string) (string, error) {
	f, err := os.Open(path.Clean(filename))
	if err != nil {
		return "", fmt.Errorf("open file: %v", err)
	}

	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash file: %v", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func main() {
	mustHandleSubcommand(os.Args[1:], os.Stdout)

	mustInitialize()

	var (
		api            = &api{config: config, requests: requests}
		cancelableJobs = newSafeMap[string, func()]()
		workers        = &sync.WaitGroup{}
	)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	go cancelableJobs.periodicCompact(ctx, 60*time.Minute)

	srv := &http.Server{
		Addr:              config.Server.ListenAddr,
		Handler:           api.newHandler(ctx, workers, cancelableJobs),
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

	protocol := "http"
	if config.Server.TLS {
		protocol = "https"
	}

	logger.Info("server listening", "addr", l.Addr().String(), "protocol", protocol)

	errCh := make(chan error, 1)
	go func(ch chan error) {
		if config.Server.TLS {
			ch <- srv.ServeTLS(
				l,
				config.Server.CertFile,
				config.Server.KeyFile,
			)
		} else {
			ch <- srv.Serve(l)
		}

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

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("server shutdown error", "err", err)
	}

	shutdownCancel()
	workers.Wait()

	if err := requests.close(); err != nil {
		logger.Error("close request store", "err", err)
	}

	if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server exit error", "err", err)
	}

	logger.Info("server stopped")

	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		os.Exit(1)
	}
}
