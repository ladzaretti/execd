package main

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"
)

type Config struct {
	LogLevel   string     `json:"log_level,omitempty"   toml:"log_level,commented"`
	Token      string     `json:"token,omitempty"       toml:"token,commented"`
	ListenAddr string     `json:"listen_addr,omitempty" toml:"listen_addr,commented"`
	Endpoints  []Endpoint `json:"endpoints,omitempty"   toml:"endpoints,commented"`
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

		if e.Unsafe {
			logger.Warn("endpoint registered without token protection (unsafe mode enabled)",
				"path", e.Path,
				"index", i,
			)
		} else if c.Token == "" && e.Token == "" {
			return fmt.Errorf("token missing for path: %q: set global token or endpoint[%d].token", e.Path, i)
		}

		if _, dup := seen[e.Path]; dup {
			return fmt.Errorf("duplicate endpoint: %s", e.Path)
		}

		seen[e.Path] = struct{}{}
	}

	return nil
}

func (c *Config) setDefaults() error {
	if c == nil {
		return errors.New("cannot set defaults on nil config")
	}

	c.ListenAddr = cmp.Or(c.ListenAddr, defaultListenAddr)

	return nil
}

func (c *Config) redact() *Config {
	if c == nil {
		return nil
	}

	redacted := *c

	if redacted.Token != "" {
		redacted.Token = redact
	}

	redacted.Endpoints = append([]Endpoint(nil), redacted.Endpoints...)
	for i, e := range redacted.Endpoints {
		redacted.Endpoints[i] = e.redact()
	}

	return &redacted
}

func (c *Config) complete() {
	for i := range c.Endpoints {
		c.Endpoints[i].complete()
	}
}

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

func loadFileConfig(path string) (*Config, error) {
	if path == "" {
		return nil, errors.New("config path must be set")
	}

	c, err := parseFileConfig(path)
	if err != nil {
		if path != "" || !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("load config %s: %w", path, err)
		}

		c = &Config{}
	}

	if err := c.setDefaults(); err != nil {
		return nil, err
	}

	if err := c.validate(); err != nil {
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
		return lvl, err
	}

	return lvl, nil
}
