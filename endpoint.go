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
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"
)

type resolvedEndpoint struct {
	path       string
	method     string
	command    string
	args       []string
	env        []string
	timeout    time.Duration
	pathParams []string
}

type Endpoint struct {
	Summary      string   `json:"summary,omitempty"       toml:"summary,commented"`
	Path         string   `json:"path,omitempty"          toml:"path,commented"`
	Token        string   `json:"token,omitempty"         toml:"token,commented"`
	Method       string   `json:"method,omitempty"        toml:"method,commented"`
	Cmd          []string `json:"cmd,omitempty"           toml:"cmd,commented"`
	EnvAllowlist []string `json:"env_allowlist,omitempty" toml:"env_allowlist,commented"`
	Detached     bool     `json:"detached,omitempty"      toml:"detached,commented"`
	UID          uint32   `json:"uid,omitempty"           toml:"uid,commented"`
	GID          uint32   `json:"gid,omitempty"           toml:"gid,commented"`
	Timeout      string   `json:"timeout,omitempty"       toml:"timeout,commented"`
	NoAuth       bool     `json:"no_auth,omitempty"       toml:"no_auth,commented"`

	resolvedEndpoint
}

func (e *Endpoint) validate() error {
	if e.Path == "" {
		return errors.New("route path is empty")
	}

	if e.Method != "" && !slices.Contains(allowedHTTPMethods, strings.ToUpper(e.Method)) {
		return fmt.Errorf("unsupported method %q for path %q", e.Method, e.Path)
	}

	if e.Detached && e.Timeout != "" {
		return errors.New("timeout cannot be used when running in detached mode")
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

var re = regexp.MustCompile(`{([^{}]*)}`)

func (e *Endpoint) resolve() {
	e.method = cmp.Or(e.Method, http.MethodPost)
	e.command, e.args = e.Cmd[0], e.Cmd[1:]

	e.env = make([]string, 0, len(e.EnvAllowlist))
	for _, key := range e.EnvAllowlist {
		e.env = append(e.env, key+"="+os.Getenv(key))
	}

	if e.Timeout != "" {
		t, _ := time.ParseDuration(e.Timeout) // validated at [Endpoint.validate]
		e.timeout = t
	}

	e.path = filepath.Join(defaultUserPrefix, e.Path)
	e.pathParams = make([]string, 0, 4)

	matches := re.FindAllStringSubmatch(e.Path, -1)
	for _, v := range matches {
		e.pathParams = append(e.pathParams, v[1])
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

type ExecResult struct {
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
	Detached bool   `json:"detached,omitempty"`
	PID      *int   `json:"pid,omitempty"`
	ExitCode *int   `json:"exit_code,omitempty"`
	Error    string `json:"error,omitempty"`
}

func (e *Endpoint) run(ctx context.Context, env []string) *ExecResult {
	if e.Detached {
		return e.runDetached(env)
	}

	return e.runWait(ctx, env)
}

func (e *Endpoint) runWait(ctx context.Context, env []string) *ExecResult {
	if e.timeout != 0 {
		c, cancel := context.WithTimeout(ctx, e.timeout)
		ctx = c

		defer cancel()
	}

	// #nosec G204 // command and args come from trusted config
	cmd := exec.CommandContext(ctx, e.command, e.args...)

	var stdout, stderr bytes.Buffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	cmd.Env = slices.Concat(e.env, env)

	if e.UID != 0 || e.GID != 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
		cmd.SysProcAttr.Credential = &syscall.Credential{
			Uid: e.UID,
			Gid: e.GID,
		}
	}

	exitCode, execResult := -1, ExecResult{}

	err := cmd.Run()
	if err != nil {
		execResult.Error = err.Error()

		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exitCode = ee.ExitCode()
		}
	} else if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}

	execResult.Stdout = stdout.String()
	execResult.Stderr = stderr.String()
	execResult.ExitCode = &exitCode

	return &execResult
}

func (e *Endpoint) runDetached(env []string) *ExecResult {
	cmd := exec.Command(e.command, e.args...) //nolint:gosec,noctx // command and args come from trusted config // noctx is intentional
	cmd.Env = slices.Concat(e.env, env)

	if f, err := os.OpenFile("/dev/null", os.O_WRONLY, 0); err == nil {
		cmd.Stdout, cmd.Stderr, cmd.Stdin = f, f, nil
	} else {
		cmd.Stdout, cmd.Stderr, cmd.Stdin = nil, nil, nil
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	if e.UID != 0 || e.GID != 0 {
		cmd.SysProcAttr.Credential = &syscall.Credential{
			Uid: e.UID,
			Gid: e.GID,
		}
	}

	err := cmd.Start()
	if err != nil {
		return &ExecResult{Error: err.Error()}
	}

	// reap so it never zombies
	go func() { _ = cmd.Wait() }()

	return &ExecResult{
		Detached: true,
		PID:      &cmd.Process.Pid,
	}
}
