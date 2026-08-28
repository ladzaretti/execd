package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

//revive:disable:struct-tag // go-toml/v2 supports the commented TOML tag option.
type Server struct {
	LogLevel   string `comment:"Log level (default: info)."                                                 json:"log_level,omitempty"     toml:"log_level,commented"`
	DBPath     string `comment:"SQLite database path (default: XDG cache directory/.execd.d/execd.sqlite)." json:"database_path,omitempty" toml:"database_path,commented"`
	Password   string `comment:"Bearer token for protected endpoints (required)."                           json:"password,omitempty"      toml:"password"`
	ListenAddr string `comment:"Listen address (required)."                                                 json:"listen_addr,omitempty"   toml:"listen_addr"`
	TLS        bool   `comment:"Enable TLS."                                                                json:"tls,omitempty"           toml:"tls,commented"`
	CertFile   string `comment:"TLS certificate file (required when tls is true)."                          json:"cert_file,omitempty"     toml:"cert_file,commented"`
	KeyFile    string `comment:"TLS private key file (required when tls is true)."                          json:"key_file,omitempty"      toml:"key_file,commented"`
}

type Config struct {
	Server    Server     `json:"server,omitempty"    toml:"server"`
	Endpoints []Endpoint `json:"endpoints,omitempty" toml:"endpoints"`

	configPath string
	sha        string
}

//revive:enable:struct-tag

func (c *Config) validate() error {
	uid := os.Getuid()

	if c.Server.ListenAddr == "" {
		return errors.New("listen_addr must not be empty")
	}

	if c.Server.Password == "" {
		return errors.New("server password must not be empty")
	}

	if _, _, err := net.SplitHostPort(c.Server.ListenAddr); err != nil {
		return fmt.Errorf("listen_addr must be host:port or :port: %v", err)
	}

	_, err := parseLogLevel(c.Server.LogLevel)
	if err != nil {
		return fmt.Errorf("invalid log level: %v", err)
	}

	seen := make(map[string]struct{}, len(c.Endpoints))
	for i, e := range c.Endpoints {
		if err := e.validate(); err != nil {
			return fmt.Errorf("endpoint[%d]: %v", i, err)
		}

		if err := validateRoutePattern(e.Method, e.Path); err != nil {
			return fmt.Errorf("endpoint[%d]: %v", i, err)
		}

		if (e.UID != 0 || e.GID != 0) && uid != 0 {
			return fmt.Errorf("cannot set UID/GID for endpoint %q: must run as root to drop privileges (current uid=%d, requested uid=%d gid=%d)", e.Path, uid, e.UID, e.GID)
		}

		if e.NoAuth {
			logger.Warn("endpoint registered without password protection (unsafe mode enabled)",
				"path", e.Path,
				"index", i,
			)
		}

		if _, dup := seen[e.Path]; dup {
			return fmt.Errorf("duplicate endpoint: %s", e.Path)
		}

		seen[e.Path] = struct{}{}
	}

	return nil
}

func (c *Config) resolve() error {
	if c == nil {
		return errors.New("cannot set defaults on nil config")
	}

	return nil
}

func (c *Config) redact() *Config {
	if c == nil {
		return nil
	}

	redacted := *c
	redacted.Endpoints = append([]Endpoint(nil), redacted.Endpoints...)

	if redacted.Server.Password != "" {
		redacted.Server.Password = redact
	}

	return &redacted
}

func (c *Config) complete() {
	for i := range c.Endpoints {
		c.Endpoints[i].resolve()
	}
}

func newDefaultConfig() Config {
	return Config{
		Server: Server{ListenAddr: ":8443"},
		Endpoints: []Endpoint{
			{
				Summary: "Health check.",
				Path:    "/ping",
				Method:  "GET",
				Cmd:     []string{"/usr/bin/echo", "pong"},
			},
		},
	}
}

func writeDefaultConfig(w io.Writer) error {
	if err := toml.NewEncoder(w).Encode(newDefaultConfig()); err != nil {
		return fmt.Errorf("encode default config: %v", err)
	}

	return nil
}

func defaultConfigPath() (string, error) {
	home, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("get user config directory: %v", err)
	}

	return filepath.Join(home, defaultConfigName), nil
}

func resolveConfigPath(path string) (string, error) {
	if path != "" {
		return path, nil
	}

	return defaultConfigPath()
}

func parseFileConfig(path string) (*Config, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("config: stat file: %v", err)
	}

	if fi.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("config: %q has invalid permissions: got %04o, expected 0600", path, fi.Mode().Perm())
	}

	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read config file: %v", err)
	}

	var config Config
	if err := toml.NewDecoder(bytes.NewReader(raw)).DisallowUnknownFields().Decode(&config); err != nil {
		if strictErr, ok := errors.AsType[*toml.StrictMissingError](err); ok {
			return nil, fmt.Errorf("config: unknown fields: %s", strings.Join(unknownFieldDetails(strictErr.Errors), ", "))
		}

		return nil, fmt.Errorf("config: parse file: %v", err)
	}

	return &config, nil
}

func unknownFieldDetails(decodeErrors []toml.DecodeError) []string {
	unknownFields := make([]string, 0, len(decodeErrors))

	for _, unknownField := range decodeErrors {
		line, column := unknownField.Position()
		unknownFields = append(unknownFields,
			fmt.Sprintf("%q (line %d, column %d)",
				strings.Join(unknownField.Key(), "."),
				line,
				column,
			),
		)
	}

	return unknownFields
}

func loadFileConfig(path string) (*Config, error) {
	if path == "" {
		return nil, errors.New("config path must be set")
	}

	c, err := parseFileConfig(path)
	if err != nil {
		return nil, fmt.Errorf("load config %s: %v", path, err)
	}

	if err := c.validate(); err != nil {
		return nil, err
	}

	if err := c.resolve(); err != nil {
		return nil, err
	}

	c.complete()

	return c, nil
}

func parseLogLevel(s string) (slog.Level, error) {
	if s == "" {
		return slog.LevelInfo, nil
	}

	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(s)); err != nil {
		return lvl, fmt.Errorf("parse log level: %v", err)
	}

	return lvl, nil
}
