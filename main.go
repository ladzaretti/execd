package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
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
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/google/uuid"
)

var Version = "v0.0.0"

type execState string

const (
	execStateRunning   execState = "running"
	execStateQueued    execState = "queued"
	execStateCompleted execState = "completed"
	execStateFailed    execState = "failed"
	execStateCanceled  execState = "canceled"
)

const (
	defaultUserPrefix = "/exec"
	defaultConfigName = ".execd.toml"
	defaultListenAddr = ":8081"
	redact            = "*****"
)

var (
	logger             = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	config             *Config
	allowedHTTPMethods = []string{
		http.MethodGet,
		http.MethodPost,
		http.MethodPut,
		http.MethodDelete,
		http.MethodOptions,
	}
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

	c.sha = sha

	logger.Info("config sha256", "sha", c.sha)

	l, _ := parseLogLevel(c.LogLevel) // already validated during config parsing

	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
	logger.Info("resolved config", "path", configPath, "config", c.redact())

	config = c
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

func newJobsHandler(jobs *safeMap[string, RequestState]) http.Handler {
	type JobsSummary struct {
		ID          string    `json:"id,omitempty"`
		Path        string    `json:"path,omitempty"`
		State       execState `json:"state,omitempty"`
		Detached    bool      `json:"detached,omitempty"`
		PID         int       `json:"pid,omitempty"`
		ExitCode    *int      `json:"exit_code,omitempty"`
		Error       string    `json:"error,omitempty"`
		StartedAt   time.Time `json:"started_at,omitzero"`
		CompletedAt time.Time `json:"completed_at,omitzero"`
	}

	allowedFilters := []string{
		string(execStateRunning),
		string(execStateQueued),
		string(execStateCompleted),
		string(execStateFailed),
		string(execStateCanceled),
	}

	validateFilters := func(filters []string) bool {
		if len(filters) == 0 {
			return true
		}

		for _, f := range filters {
			if !slices.Contains(allowedFilters, strings.ToLower(f)) {
				return false
			}
		}

		return true
	}

	paginate := func(w http.ResponseWriter, r *http.Request, summary []JobsSummary, cursor string, limit int) {
		start := slices.IndexFunc(summary, func(e JobsSummary) bool {
			return cursor == "" || e.ID == cursor // no cursor means serve first page
		})

		if start == -1 {
			http.Error(w, "cursor does not exists", http.StatusBadRequest)

			return
		}

		end := min(start+limit, len(summary))

		page := summary[start:end]

		if end < len(summary) {
			nextCursor := summary[end].ID

			u := *r.URL
			q := u.Query()
			q.Set("cursor", nextCursor)
			q.Set("limit", strconv.Itoa(limit))
			u.RawQuery = q.Encode()

			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}

			u.Scheme, u.Host = scheme, r.Host

			w.Header().Set("Link", fmt.Sprintf("<%s>; rel=\"next\"", u.String()))
		}

		writeJSON(w, http.StatusOK, page)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

			return
		}

		summary := make([]JobsSummary, 0, jobs.len())
		filters := make([]string, 0, len(allowedFilters))

		for _, s := range r.URL.Query()["filter"] {
			filters = append(filters, strings.Split(s, ",")...)
		}

		if !validateFilters(filters) {
			http.Error(
				w,
				"allowed filters: "+strings.Join(allowedFilters, ","),
				http.StatusBadRequest,
			)

			return
		}

		jobs.safeRange(func(k string, v RequestState) {
			if len(filters) > 0 && !slices.Contains(filters, string(v.State)) {
				return
			}

			summary = append(summary, JobsSummary{
				ID:          k,
				Path:        v.Path,
				State:       v.State,
				Detached:    v.Result.Detached,
				PID:         v.Result.PID,
				ExitCode:    v.Result.ExitCode,
				Error:       v.Result.Error,
				StartedAt:   v.StartedAt,
				CompletedAt: v.CompletedAt,
			})
		})

		slices.SortFunc(summary, func(a, b JobsSummary) int {
			return b.StartedAt.Compare(a.StartedAt) // descent
		})

		var (
			limit  = r.URL.Query().Get("limit")
			cursor = r.URL.Query().Get("cursor")
		)

		if limit == "" {
			writeJSON(w, http.StatusOK, summary)

			return
		}

		l, err := strconv.Atoi(limit)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid limit: %s", err), http.StatusBadRequest)

			return
		}

		paginate(w, r, summary, cursor, l)
	})
}

func newJobHandler(jobs *safeMap[string, RequestState]) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "missing job id", http.StatusBadRequest)
			return
		}

		job, ok := jobs.load(id)
		if !ok {
			http.Error(w, "job not found", http.StatusNotFound)
			return
		}

		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, job)

		case http.MethodDelete:
			if job.cancel == nil {
				http.Error(w, "job not cancellable", http.StatusBadRequest)
				return
			}

			job.cancel()

			w.WriteHeader(http.StatusNoContent)

		default:
			w.Header().Set("Allow", "GET, DELETE")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

func toEnvKey(s string) (key string) {
	buf := &bytes.Buffer{}

	for i, r := range s {
		if unicode.IsUpper(r) && i > 0 {
			buf.WriteRune('_')
		}

		buf.WriteRune(unicode.ToUpper(r))
	}

	return buf.String()
}

func paramsToEnv(r *http.Request, pathParams []string) []string {
	params := r.URL.Query()
	env := make([]string, 0, len(params)+len(pathParams))

	for k, v := range params {
		env = append(env, toEnvKey(k)+"="+strings.Join(v, " "))
	}

	for _, k := range pathParams {
		env = append(env, toEnvKey(k)+"="+r.PathValue(k))
	}

	return env
}

func newExecHandler(appCtx context.Context, e Endpoint, jobs *safeMap[string, RequestState]) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, ok := r.Context().Value(requestKey).(string)
		if !ok {
			v = ""
		}

		id := v

		jobs.store(id, RequestState{
			State:     execStateQueued,
			StartedAt: time.Now(),
			Path:      e.Path,
		})

		w.Header().Set("Location", "/jobs/"+id)
		writeJSON(w, http.StatusAccepted, struct {
			ID string `json:"id,omitempty"`
		}{ID: id})

		go runRequest(appCtx, e, jobs, id, paramsToEnv(r, e.pathParams))
	})
}

func runRequest(ctx context.Context, e Endpoint, jobs *safeMap[string, RequestState], id string, env []string) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs.upsert(id, func(old RequestState) RequestState {
		old.State, old.cancel = execStateRunning, cancel
		return old
	})

	execResult := e.run(ctx, env)

	completed := RequestState{
		State:       execStateCompleted,
		CompletedAt: time.Now(),
		cancel:      nil,
	}

	if execResult != nil {
		completed.Result = *execResult
	}

	if execResult.Error != "" || (execResult.ExitCode != nil && *execResult.ExitCode != 0) {
		completed.State = execStateFailed
	}

	jobs.upsert(id, func(old RequestState) RequestState {
		completed.Path = old.Path
		completed.StartedAt = old.StartedAt

		return completed
	})

	go deleteJobAfter(ctx, jobs, id, 60*time.Minute)
}

func newRoutesHandler(es []Endpoint) http.Handler {
	type route struct {
		Summary string   `json:"summary,omitempty"`
		Path    string   `json:"path,omitempty"`
		Cmd     []string `json:"cmd,omitempty"`
		Timeout string   `json:"timeout,omitempty"`
		Auth    bool     `json:"requires_auth"`
	}

	routes := make([]route, len(es))

	for i, e := range es {
		routes[i] = route{
			Summary: e.Summary,
			Path: fmt.Sprintf(
				"%s %s",
				strings.ToUpper(e.method),
				path.Join(defaultUserPrefix, e.Path),
			),
			Cmd:     e.Cmd,
			Timeout: e.Timeout,
			Auth:    !e.NoAuth,
		}
	}

	payload, err := json.Marshal(routes)
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "failed to marshal routes", http.StatusInternalServerError)
		})
	}

	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		_, _ = w.Write(payload)
	})
}

func deleteJobAfter(ctx context.Context, jobs *safeMap[string, RequestState], id string, after time.Duration) {
	select {
	case <-time.After(after):
		jobs.delete(id)
	case <-ctx.Done():
		return
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(v); err != nil {
		logger.Warn("encode/write response failed", "err", err)
	}
}

func withAuth(token string, unsafe bool) func(h http.Handler) http.Handler { //nolint:revive //unused-parameter
	const bearer = "Bearer "

	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions || unsafe {
				h.ServeHTTP(w, r)
				return
			}

			auth := r.Header.Get("Authorization")
			if len(auth) < len(bearer) || !strings.EqualFold(auth[:len(bearer)], bearer) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			got, want := []byte(auth[len(bearer):]), []byte(token)
			if subtle.ConstantTimeCompare(got, want) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			h.ServeHTTP(w, r)
		})
	}
}

func withCORS(h http.Handler) http.Handler {
	methods := strings.Join(allowedHTTPMethods, ", ")

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

		h.ServeHTTP(w, r)
	})
}

type ctxKey string

var requestKey ctxKey = "requestKey"

type statusWriter struct {
	http.ResponseWriter

	status int
	n      int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}

	n, err := w.ResponseWriter.Write(b)
	w.n += n

	return n, err
}

func withTracing(h http.Handler) http.Handler {
	const hdrRequestID = "X-Request-Id"

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(hdrRequestID)
		if id == "" {
			id = uuid.NewString()
		}

		ctx := context.WithValue(r.Context(), requestKey, id)

		sw := &statusWriter{ResponseWriter: w}
		sw.Header().Set(hdrRequestID, id)

		logger.Debug("request received",
			"id", id,
			"path", r.URL.Path,
			"method", r.Method,
			"remote", r.RemoteAddr,
		)

		defer func(start time.Time) {
			logger.Debug("request completed",
				"id", id,
				"status", sw.status,
				"bytes", sw.n,
				"duration", time.Since(start).String(),
			)
		}(time.Now())

		h.ServeHTTP(sw, r.WithContext(ctx))
	})
}

func withMeta(h http.Handler) http.Handler {
	const (
		hdrConfigSHA = "X-Config-Sha"
		hdrVersion   = "X-Execd-Version"
	)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(hdrConfigSHA, config.sha)
		w.Header().Set(hdrVersion, Version)

		h.ServeHTTP(w, r)
	})
}

func chain(h http.Handler, middlewares ...func(h http.Handler) http.Handler) http.Handler {
	for _, m := range middlewares {
		h = m(h)
	}

	return h
}

type RequestState struct {
	Path        string     `json:"path,omitempty"`
	State       execState  `json:"state,omitempty"`
	Result      ExecResult `json:"result"`
	StartedAt   time.Time  `json:"started_at,omitzero"`
	CompletedAt time.Time  `json:"completed_at,omitzero"`
	cancel      func()
}

func main() {
	subcommands()

	mustInitialize()

	mux, execResults := http.NewServeMux(), newSafeMap[string, RequestState]()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	go execResults.periodicCompact(ctx, 60*time.Minute)

	for _, e := range config.Endpoints {
		h, token := newExecHandler(ctx, e, execResults), cmp.Or(e.Token, config.Token)
		pattern := fmt.Sprintf(
			"%s %s",
			strings.ToUpper(e.method),
			path.Join(defaultUserPrefix, e.Path),
		)

		mux.Handle(pattern, chain(h,
			withAuth(token, e.NoAuth),
			withMeta,
			withCORS,
			withTracing,
		))
	}

	mux.Handle("GET /jobs/{id}", chain(newJobHandler(execResults),
		withMeta,
		withCORS,
		withTracing,
	))

	mux.Handle("GET /jobs", chain(newJobsHandler(execResults),
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
	go func() {
		errCh <- srv.Serve(l)
		close(errCh)
	}()

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

	if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server exit error", "err", err)
	}

	logger.Info("server stopped")

	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		os.Exit(1)
	}
}
