package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
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
	"github.com/ladzaretti/migrate"
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
	defaultCacheDir   = ".execd.d"
	defaultDBFilename = "execd.sqlite"
	defaultListenAddr = ":8081"
	redact            = "*****"
)

var (
	logger             = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	config             *Config
	execdb             *execDB
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

	c.configPath = *configPath
	c.sha = sha

	logger.Info("config sha256", "sha", c.sha)

	l, _ := parseLogLevel(c.LogLevel) // already validated during config parsing

	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
	logger.Info("resolved config", "path", configPath, "config", c.redact())

	config = c

	db, err := newExecDB(c.DBPath)
	if err != nil {
		logger.Error("exec db:", "err", err)
		os.Exit(1)
	}

	execdb = db
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

func newJobsHandler() http.Handler {
	type JobsSummary struct {
		ID          string    `json:"id,omitempty"`
		Path        string    `json:"path,omitempty"`
		State       execState `json:"state,omitempty"`
		Detached    bool      `json:"detached,omitempty"`
		PID         *int      `json:"pid,omitempty"`
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

	writeResp := func(w http.ResponseWriter, r *http.Request, page []JobsSummary, next *JobsSummary, limit int) {
		if next != nil {
			u := *r.URL
			q := u.Query()
			q.Set("cursor", next.ID)
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

	convert := func(r RequestState) JobsSummary {
		return JobsSummary{
			ID:          r.UUID,
			Path:        r.Path,
			State:       r.State,
			Detached:    r.Result.Detached,
			PID:         r.Result.PID,
			ExitCode:    r.Result.ExitCode,
			Error:       r.Result.Error,
			StartedAt:   r.StartedAt,
			CompletedAt: r.CompletedAt,
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

			return
		}

		var (
			cursor     = r.URL.Query().Get("cursor")
			pagination = len(r.URL.Query().Get("limit")) > 0
			filters    = make([]string, 0, len(allowedFilters))
		)

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

		raw := r.URL.Query().Get("limit")

		limit, err := parseInt(raw, 0)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid limit: %s", err), http.StatusBadRequest)

			return
		}

		additional := 0
		if limit != 0 {
			additional = 1
		}

		ctx := r.Context()

		requests, err := execdb.selectRequests(ctx, cursor, filters, limit+additional)
		if err != nil {
			http.Error(
				w,
				"select requests: "+err.Error(),
				http.StatusInternalServerError,
			)

			return
		}

		summary := make([]JobsSummary, 0, len(requests))

		for _, r := range requests {
			summary = append(summary, convert(r))
		}

		var (
			next *JobsSummary
			page = summary
		)

		if pagination && len(summary) > limit {
			n := convert(requests[limit])
			next = &n

			page = summary[:limit]
		}

		writeResp(w, r, page, next, limit)
	})
}

func newJobHandler(appCtx context.Context, cancelableJobs *safeMap[string, func()]) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "missing job id", http.StatusBadRequest)
			return
		}

		switch r.Method {
		case http.MethodGet:
			ctx := r.Context()

			//nolint:contextcheck // request ctx
			job, err := execdb.selectRequestByUUID(ctx, id)
			if err != nil {
				http.Error(w, "job not found: "+err.Error(), http.StatusNotFound)

				return
			}

			writeJSON(w, http.StatusOK, job)

		case http.MethodDelete:
			cancel, ok := cancelableJobs.load(id)
			if !ok {
				http.Error(w, "job not found", http.StatusNotFound)
				return
			}

			if cancel == nil {
				http.Error(w, "job not cancellable", http.StatusBadRequest)
				return
			}

			cancel()

			w.WriteHeader(http.StatusNoContent)

			if _, err := execdb.updateRequestState(appCtx, id, execStateCanceled); err != nil {
				logger.Error("error persisting canceled request state", "err", err)
			}

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

func parseInt(s string, fallback int) (int, error) {
	if s == "" {
		return fallback, nil
	}

	l, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}

	return l, nil
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

func newExecHandler(appCtx context.Context, e Endpoint, cancelableJobs *safeMap[string, func()]) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, ok := r.Context().Value(requestKey).(string)
		if !ok {
			v = ""
		}

		id := v

		w.Header().Set("Location", "/jobs/"+id)
		writeJSON(w, http.StatusAccepted, struct {
			ID string `json:"id,omitempty"`
		}{ID: id})

		rs := RequestState{
			State:     execStateQueued,
			StartedAt: time.Now(),
			Path:      e.path,
		}
		if _, err := execdb.insertNewRequest(appCtx, id, rs); err != nil {
			logger.Error("error saving new request to database", "err", err)
		}

		go runRequest(appCtx, e, cancelableJobs, id, paramsToEnv(r, e.pathParams))
	})
}

func runRequest(ctx context.Context, e Endpoint, cancelableJobs *safeMap[string, func()], id string, env []string) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cancelableJobs.store(id, cancel)

	if _, err := execdb.updateRequestState(ctx, id, execStateRunning); err != nil {
		logger.Error("error persisting running request state", "err", err)
	}

	execResult := e.run(ctx, env)

	completed := RequestState{
		State:       execStateCompleted,
		CompletedAt: time.Now(),
	}

	if execResult != nil {
		completed.Result = *execResult
	}

	if execResult.Error != "" || (execResult.ExitCode != nil && *execResult.ExitCode != 0) {
		completed.State = execStateFailed
	}

	if _, err := execdb.completeRequest(ctx, id, completed); err != nil {
		logger.Error("error persisting completed request data", "err", err)
	}

	cancelableJobs.delete(id)
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
			Path:    fmt.Sprintf("%s %s", strings.ToUpper(e.method), e.path),
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
			u, _ := uuid.NewV7()
			id = u.String()
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
	UUID        string     `json:"uuid,omitempty"`
	Path        string     `json:"path,omitempty"`
	State       execState  `json:"state,omitempty"`
	Result      ExecResult `json:"result,omitempty"`
	StartedAt   time.Time  `json:"started_at,omitzero,omitempty"`
	CompletedAt time.Time  `json:"completed_at,omitzero,omitempty"`
}

var (
	//go:embed migrations
	embedFS    embed.FS
	migrations = migrate.EmbeddedMigrations{
		FS:   embedFS,
		Path: "migrations",
	}
)

func main() {
	subcommands()

	mustInitialize()

	mux, cancelableJobs := http.NewServeMux(), newSafeMap[string, func()]()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	go cancelableJobs.periodicCompact(ctx, 60*time.Minute)

	for _, e := range config.Endpoints {
		h, token := newExecHandler(ctx, e, cancelableJobs), cmp.Or(e.Token, config.Token)
		pattern := fmt.Sprintf(
			"%s %s",
			strings.ToUpper(e.method),
			e.path,
		)

		mux.Handle(pattern, chain(h,
			withAuth(token, e.NoAuth),
			withMeta,
			withCORS,
			withTracing,
		))
	}

	mux.Handle("GET /jobs/{id}", chain(newJobHandler(ctx, cancelableJobs),
		withMeta,
		withCORS,
		withTracing,
	))

	mux.Handle("GET /jobs", chain(newJobsHandler(),
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
	go func(ch chan error) {
		ch <- srv.Serve(l)

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

	_ = execdb.close()

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
