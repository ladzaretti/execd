package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
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

const (
	defaultJobsPageSize = 100
	maxJobsPageSize     = 1000
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

type api struct {
	config   *Config
	requests *requestStore
}

func (a *api) newExecHandler(appCtx context.Context, workers *sync.WaitGroup, e Endpoint, cancelableJobs *safeMap[string, func()]) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, err := uuid.NewV7()
		if err != nil {
			http.Error(w, "generate job ID", http.StatusInternalServerError)
			return
		}

		id := u.String()

		rs := RequestState{
			State:     execStateQueued,
			StartedAt: time.Now(),
			Path:      e.path,
		}
		if _, err := a.requests.insert(appCtx, id, rs); err != nil {
			logger.Error("save new request to database", "err", err)
			http.Error(w, "save request", http.StatusInternalServerError)

			return
		}

		location := path.Join("/", "jobs", url.PathEscape(id))
		w.Header().Set("Location", location)
		writeJSON(w, http.StatusAccepted, struct {
			ID       string `json:"id,omitempty"`
			Location string `json:"location,omitempty"`
		}{
			ID:       id,
			Location: location,
		})

		workers.Go(func() {
			a.runRequest(appCtx, e, cancelableJobs, id, paramsToEnv(r, e.pathParams))
		})
	})
}

func (a *api) runRequest(ctx context.Context, e Endpoint, cancelableJobs *safeMap[string, func()], id string, env []string) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	persistenceCtx := context.WithoutCancel(ctx)

	cancelableJobs.store(id, cancel)
	defer cancelableJobs.delete(id)

	if _, err := a.requests.updateState(persistenceCtx, id, execStateRunning); err != nil {
		logger.Error("persist running request", "err", err)
	}

	execResult := e.run(ctx, env)

	completed := RequestState{
		State:       execStateCompleted,
		CompletedAt: time.Now(),
	}

	if execResult != nil {
		completed.Result = *execResult
	}

	if errors.Is(ctx.Err(), context.Canceled) {
		completed.State = execStateCanceled
	} else if execResult.Error != "" ||
		(execResult.ExitCode != nil && *execResult.ExitCode != 0) {
		completed.State = execStateFailed
	}

	if _, err := a.requests.complete(persistenceCtx, id, completed); err != nil {
		logger.Error("persist completed request", "err", err)
	}
}

func (a *api) newJobsHandler() http.Handler {
	type JobsSummary struct {
		ID              string    `json:"id,omitempty"`
		Path            string    `json:"path,omitempty"`
		State           execState `json:"state,omitempty"`
		Detached        bool      `json:"detached,omitempty"`
		OutputTruncated bool      `json:"output_truncated,omitempty"`
		PID             *int      `json:"pid,omitempty"`
		ExitCode        *int      `json:"exit_code,omitempty"`
		Error           string    `json:"error,omitempty"`
		StartedAt       time.Time `json:"started_at,omitzero"`
		CompletedAt     time.Time `json:"completed_at,omitzero"`
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

			u.Scheme, u.Host = "", ""

			w.Header().Set("Link", fmt.Sprintf("<%s>; rel=\"next\"", u.String()))
		}

		writeJSON(w, http.StatusOK, page)
	}

	convert := func(r RequestState) JobsSummary {
		return JobsSummary{
			ID:              r.UUID,
			Path:            r.Path,
			State:           r.State,
			Detached:        r.Result.Detached,
			OutputTruncated: r.Result.OutputTruncated,
			PID:             r.Result.PID,
			ExitCode:        r.Result.ExitCode,
			Error:           r.Result.Error,
			StartedAt:       r.StartedAt,
			CompletedAt:     r.CompletedAt,
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

			return
		}

		var (
			cursor  = r.URL.Query().Get("cursor")
			filters = make([]string, 0, len(allowedFilters))
		)

		for _, s := range r.URL.Query()["filter"] {
			for _, filter := range strings.Split(s, ",") {
				filters = append(filters, strings.ToLower(strings.TrimSpace(filter)))
			}
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

		limit, err := parseInt(raw, defaultJobsPageSize)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid limit: %s", err), http.StatusBadRequest)

			return
		}

		if limit <= 0 || limit > maxJobsPageSize {
			http.Error(w, fmt.Sprintf("limit must be between 1 and %d", maxJobsPageSize), http.StatusBadRequest)

			return
		}

		ctx := r.Context()

		reqs, err := a.requests.selectPage(ctx, cursor, filters, limit+1)
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

		if len(summary) > limit {
			n := convert(reqs[limit])
			next = &n

			page = summary[:limit]
		}

		writeResp(w, r, page, next, limit)
	})
}

func (a *api) newJobHandler(cancelableJobs *safeMap[string, func()]) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "missing job id", http.StatusBadRequest)
			return
		}

		switch r.Method {
		case http.MethodGet:
			ctx := r.Context()

			job, err := a.requests.selectByUUID(ctx, id)
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

	if err != nil {
		return n, fmt.Errorf("write response: %v", err)
	}

	return n, nil
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
		return 0, fmt.Errorf("parse integer: %v", err)
	}

	return l, nil
}

var internalEndpoints = []Endpoint{
	{
		Summary: "Retrieve job details by ID.",
		resolvedEndpoint: resolvedEndpoint{
			path:   path.Join("/", "jobs", "{id}"),
			method: "GET",
		},
	},
	{
		Summary: "List recently completed jobs.",
		resolvedEndpoint: resolvedEndpoint{
			path:   path.Join("/", "jobs"),
			method: "GET",
		},
	},
	{
		Summary: "List all user defined execution routes.",
		resolvedEndpoint: resolvedEndpoint{
			path:   path.Join("/", "user-routes"),
			method: "GET",
		},
	},
}

func (a *api) newExecRoutes(ctx context.Context, cancelableJobs *safeMap[string, func()], workers *sync.WaitGroup) *http.ServeMux {
	mux := http.NewServeMux()

	for _, e := range a.config.Endpoints {
		h := a.newExecHandler(ctx, workers, e, cancelableJobs)

		pattern := fmt.Sprintf(
			"%s %s",
			strings.ToUpper(e.method),
			e.path,
		)

		mux.Handle(pattern, chain(h,
			withSecurityHeaders,
			withAuth(a.config.Server.Password, authEnabled(!e.NoAuth)),
			withMeta(a.config.sha),
			withTracing,
		))
	}

	return mux
}

func (a *api) newAPIRoutes(cancelableJobs *safeMap[string, func()]) *http.ServeMux {
	mux := http.NewServeMux()

	mux.Handle("GET /jobs/{id}", chain(a.newJobHandler(cancelableJobs),
		withSecurityHeaders,
		withAuth(a.config.Server.Password),
		withMeta(a.config.sha),
		withTracing,
	))

	mux.Handle("GET /jobs", chain(a.newJobsHandler(),
		withSecurityHeaders,
		withAuth(a.config.Server.Password),
		withMeta(a.config.sha),
		withTracing,
	))

	mux.Handle("GET /user-routes", chain(newUserRoutesHandler(append(internalEndpoints, a.config.Endpoints...)),
		withSecurityHeaders,
		withAuth(a.config.Server.Password),
		withMeta(a.config.sha),
		withTracing,
	))

	return mux
}

func (a *api) newHandler(ctx context.Context, workers *sync.WaitGroup, cancelableJobs *safeMap[string, func()]) http.Handler {
	root := http.NewServeMux()

	root.Handle(defaultUserPrefix+"/", a.newExecRoutes(ctx, cancelableJobs, workers))
	root.Handle("/", a.newAPIRoutes(cancelableJobs))

	return root
}
