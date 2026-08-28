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
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"
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

//revive:disable:struct-tag // go-toml/v2 supports the commented TOML tag option.
type Endpoint struct {
	resolvedEndpoint

	Summary      string   `comment:"Human-readable route description."                                                                    json:"summary,omitempty"       toml:"summary"`
	Path         string   `comment:"Route path below /exec (required)."                                                                   json:"path,omitempty"          toml:"path"`
	Method       string   `comment:"HTTP method (default: POST)."                                                                         json:"method,omitempty"        toml:"method"`
	Cmd          []string `comment:"Fixed command and arguments (required)."                                                              json:"cmd,omitempty"           toml:"cmd"`
	EnvAllowlist []string `comment:"Environment variables inherited from execd."                                                          json:"env_allowlist,omitempty" toml:"env_allowlist,commented"`
	Detached     bool     `comment:"Start without waiting for completion."                                                                json:"detached,omitempty"      toml:"detached,commented"`
	UID          uint32   `comment:"UID to run as (requires execd to run as root)."                                                       json:"uid,omitempty"           toml:"uid,commented"`
	GID          uint32   `comment:"GID to run as (requires execd to run as root)."                                                       json:"gid,omitempty"           toml:"gid,commented"`
	Timeout      string   `comment:"Maximum execution time as a Go duration (for example: 30s, 5m); not available for detached commands." json:"timeout,omitempty"       toml:"timeout,commented"`
	NoAuth       bool     `comment:"Disable authentication for this execution route."                                                     json:"no_auth,omitempty"       toml:"no_auth,commented"`
}

//revive:enable:struct-tag

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

	if path.Clean(e.Path) != e.Path {
		return fmt.Errorf("invalid route path %q: must not contain dot segments", e.Path)
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

	e.path = path.Join(defaultUserPrefix, e.Path)
	e.pathParams = make([]string, 0, 4)

	matches := re.FindAllStringSubmatch(e.Path, -1)
	for _, v := range matches {
		e.pathParams = append(e.pathParams, strings.TrimSuffix(v[1], "..."))
	}
}

type ExecResult struct {
	Stdout          string `json:"stdout,omitempty"`
	Stderr          string `json:"stderr,omitempty"`
	OutputTruncated bool   `json:"output_truncated,omitempty"`
	Detached        bool   `json:"detached,omitempty"`
	PID             *int   `json:"pid,omitempty"`
	ExitCode        *int   `json:"exit_code,omitempty"`
	Error           string `json:"error,omitempty"`
}

const (
	maxCapturedOutputBytes = 1 << 20
	commandTermGrace       = 5 * time.Second
	commandWaitDelay       = 10 * time.Second
)

type limitedBuffer struct {
	bytes.Buffer

	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := maxCapturedOutputBytes - b.Len()

	if remaining < n {
		b.truncated = true

		if remaining <= 0 {
			return n, nil
		}

		p = p[:remaining]
	}

	_, _ = b.Buffer.Write(p)

	return n, nil
}

func validateRoutePattern(method, endpointPath string) (err error) {
	pattern := fmt.Sprintf("%s %s", strings.ToUpper(cmp.Or(method, http.MethodPost)), path.Join(defaultUserPrefix, endpointPath))

	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("invalid route pattern %q: %v", pattern, recovered)
		}
	}()

	http.NewServeMux().Handle(pattern, http.NotFoundHandler())

	return nil
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

	var stdout, stderr limitedBuffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = slices.Concat(e.env, env)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = gracefulCancel(cmd)
	cmd.WaitDelay = commandWaitDelay

	if e.UID != 0 || e.GID != 0 {
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
	execResult.OutputTruncated = stdout.truncated || stderr.truncated
	execResult.ExitCode = &exitCode

	return &execResult
}

func gracefulCancel(cmd *exec.Cmd) func() error {
	var killOnce sync.Once

	return func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}

		pid := cmd.Process.Pid

		err := syscall.Kill(pid, syscall.SIGTERM)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}

		if err != nil {
			return fmt.Errorf("terminate process: %v", err)
		}

		killOnce.Do(func() {
			time.AfterFunc(commandTermGrace, func() {
				_ = syscall.Kill(-pid, syscall.SIGKILL)
			})
		})

		return nil
	}
}

func (e *Endpoint) runDetached(env []string) *ExecResult {
	cmd := exec.Command(e.command, e.args...) //nolint:gosec,noctx // command and args come from trusted config // noctx is intentional
	cmd.Env = slices.Concat(e.env, env)

	if f, err := os.OpenFile("/dev/null", os.O_WRONLY, 0); err != nil {
		cmd.Stdout, cmd.Stderr, cmd.Stdin = nil, nil, nil
	} else {
		defer func() { _ = f.Close() }()

		cmd.Stdout, cmd.Stderr, cmd.Stdin = f, f, nil
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
