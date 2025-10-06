package main

import (
	"bytes"
	"cmp"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

type Endpoint struct {
	Path   string   `json:"path,omitempty" toml:"path,commented"`
	Token  string   `json:"token,omitempty" toml:"token,commented"`
	Method string   `json:"method,omitempty" toml:"method,commented"`
	Cmd    []string `json:"cmd,omitempty" toml:"cmd,commented"`
}

var allowedHTTPMethods []string = []string{
	http.MethodGet,
	http.MethodPost,
	http.MethodPut,
	http.MethodDelete,
	http.MethodOptions,
}

func (e Endpoint) validate() error {
	if e.Path == "" {
		return errors.New("route path is empty")
	}

	if e.Method != "" && !slices.Contains(allowedHTTPMethods, strings.ToUpper(e.Method)) {
		return fmt.Errorf("unsupported method %q for path %q", e.Method, e.Path)
	}

	if !strings.HasPrefix(e.Path, "/") {
		return fmt.Errorf("invalid route path %q: must start with '/'", e.Path)
	}

	if strings.HasSuffix(e.Path, "/") {
		return fmt.Errorf("invalid route path %q: must not end with '/'", e.Path)
	}

	if len(e.Cmd) == 0 || e.Cmd[0] == "" {
		return errors.New("cmd must be a non-empty argv")
	}

	return nil
}

func (e Endpoint) redact() Endpoint {
	if e.Token == "" {
		return e
	}

	redacted := e
	redacted.Token = "*****"

	return redacted
}

type Config struct {
	LogLevel   string     `json:"log_level,omitempty" toml:"log_level,commented"`
	Token      string     `json:"token,omitempty" toml:"token,commented"`
	ListenAddr string     `json:"listen_addr,omitempty" toml:"listen_addr,commented"`
	Endpoints  []Endpoint `json:"endpoints,omitempty" toml:"endpoints,commented"`
}

func (c *Config) validate() error {
	if c.ListenAddr == "" {
		return errors.New("listen_addr must not be empty")
	}

	if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
		return fmt.Errorf("listen_addr must be host:port or :port: %w", err)
	}

	seen := make(map[string]struct{}, len(c.Endpoints))
	for i, e := range c.Endpoints {
		if err := e.validate(); err != nil {
			return fmt.Errorf("endpoint[%d]: %w", i, err)
		}

		if c.Token == "" && e.Token == "" {
			return fmt.Errorf("token missing for path: %q: set global token or endpoint[%d].token", e.Path, i)
		}

		if _, dup := seen[e.Path]; dup {
			return fmt.Errorf("duplicate endpoint: %s", e.Path)
		}

		seen[e.Path] = struct{}{}
	}

	return nil
}

// setDefaults fills zero-valued optional fields.
func (c *Config) setDefaults() error {
	if c == nil {
		return errors.New("cannot set defaults on nil config")
	}

	c.ListenAddr = cmp.Or(c.ListenAddr, defaultListenAddr)

	for i, e := range c.Endpoints {
		c.Endpoints[i].Method = cmp.Or(e.Method, http.MethodPost)
	}

	return nil
}

func (c *Config) redact() *Config {
	if c == nil {
		return nil
	}

	redacted := *c

	if redacted.Token != "" {
		redacted.Token = "*****"
	}

	redacted.Endpoints = append([]Endpoint(nil), redacted.Endpoints...)
	for i, e := range redacted.Endpoints {
		redacted.Endpoints[i] = e.redact()
	}

	return &redacted
}

const (
	defaultConfigName = ".exec.toml"
	defaultListenAddr = ":8081"
)

func defaultConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(home, defaultConfigName), nil
}

func parseFileConfig(path string) (*Config, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("config: stat file: %w", err)
	}

	if (fi.Mode().Perm() & 0o022) != 0 {
		logger.Warn("config file is writable by others", "path", path)
	}

	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}

	var config Config
	if err := toml.Unmarshal(raw, &config); err != nil {
		return nil, fmt.Errorf("config: parse file: %w", err)
	}

	return &config, nil
}

// LoadFileConfig loads the config from the given or default path.
func LoadFileConfig(path string) (*Config, error) {
	if path == "" {
		return nil, errors.New("config path must be set")
	}

	c, err := parseFileConfig(path)
	if err != nil {
		// config file not found at default location; fallback to empty config
		if path == "" && errors.Is(err, fs.ErrNotExist) {
			c = &Config{}
		} else {
			return nil, fmt.Errorf("load config %s: %w", path, err)
		}
	}

	if err := c.setDefaults(); err != nil {
		return nil, err
	}

	return c, c.validate()
}

var (
	logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	config *Config
)

func parseLogLevel(s string) (slog.Level, error) {
	if s == "" {
		return slog.LevelInfo, nil
	}

	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(s)); err != nil {
		return lvl, err
	}

	return lvl, nil
}

func mustInitialize() {
	configPath := flag.String("config", "", "config file path")
	flag.Parse()

	defaultPath, err := defaultConfigPath()
	if err != nil {
		panic(err)
	}

	*configPath = cmp.Or(*configPath, defaultPath)

	c, err := LoadFileConfig(*configPath)
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
	method := strings.ToUpper(e.Method)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			http.Error(w, fmt.Sprintf("unsupported methods: %s", r.Method), http.StatusMethodNotAllowed)
			return
		}

		cmdName, args := e.Cmd[0], e.Cmd[1:]
		if _, err := exec.LookPath(cmdName); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		cmd := exec.CommandContext(r.Context(), cmdName, args...)

		var out bytes.Buffer

		cmd.Stdout = &out
		cmd.Stderr = &out
		cmd.Env = []string{}

		if err := cmd.Run(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write(out.Bytes())
	})
}

func withAuthMiddleware(token string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			h.ServeHTTP(w, r)
			return
		}

		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		h.ServeHTTP(w, r)
	})
}

func withCORS(next http.Handler) http.Handler {
	methods := strings.Join(allowedHTTPMethods, ",")

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

		next.ServeHTTP(w, r)
	})
}

func main() {
	mustInitialize()

	mux := http.NewServeMux()

	for _, e := range config.Endpoints {
		h, token := newExecHandler(e), cmp.Or(e.Token, config.Token)

		h = withAuthMiddleware(token, h)
		h = withCORS(h)

		mux.Handle(e.Path, h)
	}

	srv := &http.Server{
		Addr:         config.ListenAddr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Fatal(srv.ListenAndServe())
}
