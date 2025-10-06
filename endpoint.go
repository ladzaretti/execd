package main

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"
)

type endpointResolvedConfig struct {
	method  string
	cmd     string
	args    []string
	env     []string
	timeout time.Duration
}

type Endpoint struct {
	Path    string   `json:"path,omitempty"    toml:"path,commented"`
	Token   string   `json:"token,omitempty"   toml:"token,commented"`
	Method  string   `json:"method,omitempty"  toml:"method,commented"`
	Cmd     []string `json:"cmd,omitempty"     toml:"cmd,commented"`
	Env     []string `json:"env,omitempty"     toml:"env,commented"`
	Timeout string   `json:"timeout,omitempty" toml:"timeout,commented"`
	Unsafe  bool     `json:"unsafe,omitempty"  toml:"unsafe,commented"`

	endpointResolvedConfig
}

func (e *Endpoint) validate() error {
	if e.Path == "" {
		return errors.New("route path is empty")
	}

	if e.Method != "" && !slices.Contains(allowedHTTPMethods, strings.ToUpper(e.Method)) {
		return fmt.Errorf("unsupported method %q for path %q", e.Method, e.Path)
	}

	if e.Timeout != "" {
		if _, err := time.ParseDuration(e.Timeout); err != nil {
			return fmt.Errorf("invalid timeout duration %q for path %q", e.Timeout, e.Path)
		}
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

func (e *Endpoint) complete() {
	e.method = cmp.Or(e.Method, http.MethodPost)
	e.cmd, e.args = e.Cmd[0], e.Cmd[1:]

	e.env = make([]string, len(e.Env))
	for _, key := range e.Env {
		e.env = append(e.env, key, os.Getenv(key))
	}

	if e.Timeout != "" {
		t, _ := time.ParseDuration(e.Timeout)
		e.timeout = t
	}
}

func (e *Endpoint) redact() Endpoint {
	if e.Token == "" {
		return *e
	}

	redacted := *e
	redacted.Token = redact

	return redacted
}

func (e *Endpoint) run(ctx context.Context) ([]byte, error) {
	if _, err := exec.LookPath(e.cmd); err != nil {
		return nil, err
	}

	if e.timeout != 0 {
		c, cancel := context.WithTimeout(ctx, e.timeout)
		ctx = c

		defer cancel()
	}

	// #nosec G204 // command and args come from trusted config
	cmd := exec.CommandContext(ctx, e.cmd, e.args...)

	var out bytes.Buffer

	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.Env = e.env

	if err := cmd.Run(); err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}
