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

type Server struct {
	LogLevel   string `json:"log_level,omitempty"     toml:"log_level,commented"`
	DBPath     string `json:"database_path,omitempty" toml:"database_path,commented"`
	Token      string `json:"token,omitempty"         toml:"token,commented"`
	ListenAddr string `json:"listen_addr,omitempty"   toml:"listen_addr,commented"`
	CertFile   string `json:"cert_file,omitempty"     toml:"cert_file,commented"`
	KeyFile    string `json:"key_file,omitempty"      toml:"key_file,commented"`
}

type Config struct {
	Server    Server     `json:"server,omitempty"    toml:"server,commented"`
	Endpoints []Endpoint `json:"endpoints,omitempty" toml:"endpoints,commented"`

	configPath string
	sha        string
}

func (c *Config) validate() error {
	uid := os.Getuid()

	if c.Server.ListenAddr == "" {
		return errors.New("listen_addr must not be empty")
	}

	if c.Server.Token == "" {
		return errors.New("server token must not be empty")
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

		if (e.UID != 0 || e.GID != 0) && uid != 0 {
			return fmt.Errorf("cannot set UID/GID for endpoint %q: must run as root to drop privileges (current uid=%d, requested uid=%d gid=%d)", e.Path, uid, e.UID, e.GID)
		}

		if e.NoAuth {
			logger.Warn("endpoint registered without token protection (unsafe mode enabled)",
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

func (c *Config) setDefaults() error {
	if c == nil {
		return errors.New("cannot set defaults on nil config")
	}

	c.Server.ListenAddr = cmp.Or(c.Server.ListenAddr, defaultListenAddr)

	return nil
}

func (c *Config) redact() *Config {
	if c == nil {
		return nil
	}

	redacted := *c
	redacted.Endpoints = append([]Endpoint(nil), redacted.Endpoints...)

	if redacted.Server.Token != "" {
		redacted.Server.Token = redact
	}

	return &redacted
}

func (c *Config) complete() {
	for i := range c.Endpoints {
		c.Endpoints[i].resolve()
	}
}

func defaultConfigPath() (string, error) {
	home, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(home, defaultConfigName), nil
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
		return nil, err
	}

	var config Config
	if err := toml.Unmarshal(raw, &config); err != nil {
		return nil, fmt.Errorf("config: parse file: %v", err)
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
			return nil, fmt.Errorf("load config %s: %v", path, err)
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
