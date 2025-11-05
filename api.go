package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

type execState string

const (
	execStateRunning   execState = "running"
	execStateQueued    execState = "queued"
	execStateCompleted execState = "completed"
	execStateFailed    execState = "failed"
	execStateCanceled  execState = "canceled"
)

var allowedHTTPMethods = []string{
	http.MethodGet,
	http.MethodPost,
	http.MethodPut,
	http.MethodDelete,
	http.MethodOptions,
}

type RequestState struct {
	UUID        string     `json:"uuid,omitempty"`
	Path        string     `json:"path,omitempty"`
	State       execState  `json:"state,omitempty"`
	Result      ExecResult `json:"result,omitempty"`
	StartedAt   time.Time  `json:"started_at,omitzero,omitempty"`
	CompletedAt time.Time  `json:"completed_at,omitzero,omitempty"`
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
		if _, err := requests.insert(appCtx, id, rs); err != nil {
			logger.Error("error saving new request to database", "err", err)
		}

		go runRequest(appCtx, e, cancelableJobs, id, paramsToEnv(r, e.pathParams))
	})
}

func runRequest(ctx context.Context, e Endpoint, cancelableJobs *safeMap[string, func()], id string, env []string) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cancelableJobs.store(id, cancel)

	if _, err := requests.updateState(ctx, id, execStateRunning); err != nil {
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

	if _, err := requests.complete(ctx, id, completed); err != nil {
		logger.Error("error persisting completed request data", "err", err)
	}

	cancelableJobs.delete(id)
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

		reqs, err := requests.selectPage(ctx, cursor, filters, limit+additional)
		if err != nil {
			http.Error(
				w,
				"select requests: "+err.Error(),
				http.StatusInternalServerError,
			)

			return
		}

		summary := make([]JobsSummary, 0, len(reqs))

		for _, r := range reqs {
			summary = append(summary, convert(r))
		}

		var (
			next *JobsSummary
			page = summary
		)

		if pagination && len(summary) > limit {
			n := convert(reqs[limit])
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
			job, err := requests.selectByUUID(ctx, id)
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

			if _, err := requests.updateState(appCtx, id, execStateCanceled); err != nil {
				logger.Error("error persisting canceled request state", "err", err)
			}

		default:
			w.Header().Set("Allow", "GET, DELETE")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

func newUserRoutesHandler(endpoints []Endpoint) http.Handler {
	type route struct {
		Summary string   `json:"summary,omitempty"`
		Path    string   `json:"path,omitempty"`
		Cmd     []string `json:"cmd,omitempty"`
		Timeout string   `json:"timeout,omitempty"`
		Auth    bool     `json:"requires_auth"`
	}

	routes := make([]route, len(endpoints))

	for i, e := range endpoints {
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(v); err != nil {
		logger.Warn("encode/write response failed", "err", err)
	}
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
	queryParams := r.URL.Query()
	env := make([]string, 0, len(queryParams)+len(pathParams))

	for k, v := range queryParams {
		env = append(env, toEnvKey(k)+"="+strings.Join(v, " "))
	}

	for _, k := range pathParams {
		env = append(env, toEnvKey(k)+"="+r.PathValue(k))
	}

	return env
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

var internalEndpoints = []Endpoint{
	{
		Summary: "Retrieve job details by ID.",
		resolvedEndpoint: resolvedEndpoint{
			path:   "/jobs/{id}",
			method: "GET",
		},
	},
	{
		Summary: "List recently completed jobs.",
		resolvedEndpoint: resolvedEndpoint{
			path:   "/jobs",
			method: "GET",
		},
	},
	{
		Summary: "List all user defined execution routes.",
		resolvedEndpoint: resolvedEndpoint{
			path:   "/user-routes",
			method: "GET",
		},
	},
}

func newAPIRoutes(ctx context.Context, cancelableJobs *safeMap[string, func()]) *http.ServeMux {
	mux := http.NewServeMux()

	for _, e := range config.Endpoints {
		h, token := newExecHandler(ctx, e, cancelableJobs), config.Server.Token
		pattern := fmt.Sprintf(
			"%s %s",
			strings.ToUpper(e.method),
			e.path,
		)

		mux.Handle(pattern, chain(h,
			withAuth(token, e.NoAuth),
			withMeta,
			withTracing,
		))
	}

	mux.Handle("GET /jobs/{id}", chain(newJobHandler(ctx, cancelableJobs),
		withMeta,
		withTracing,
	))

	mux.Handle("GET /jobs", chain(newJobsHandler(),
		withMeta,
		withTracing,
	))

	mux.Handle("GET /user-routes", chain(newUserRoutesHandler(append(internalEndpoints, config.Endpoints...)),
		withMeta,
		withTracing,
	))

	return mux
}
