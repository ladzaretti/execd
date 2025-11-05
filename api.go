package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
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

type session struct {
	csrf string
	ttl  time.Duration
	iat  time.Time
	exp  time.Time
}

func newSession(ttl time.Duration) (session, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return session{}, err
	}

	var (
		csrf = base64.RawURLEncoding.EncodeToString(raw)
		now  = time.Now()
	)

	return session{
		csrf: csrf,
		ttl:  ttl,
		iat:  now,
		exp:  now.Add(ttl),
	}, nil
}

type sessions struct {
	m *safeMap[string, session]
}

func newSessions() *sessions { return &sessions{m: newSafeMap[string, session]()} }

func (sess *sessions) login(ttl time.Duration) (sid string, s session, err error) {
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return "", session{}, fmt.Errorf("sid: %w", err)
	}

	sid = base64.RawURLEncoding.EncodeToString(raw)

	s, err = newSession(ttl)
	if err != nil {
		return "", session{}, fmt.Errorf("new session: %w", err)
	}

	sess.m.store(sid, s)

	return sid, s, nil
}

func (sess *sessions) logout(sid string) bool {
	_, ok := sess.m.load(sid)
	if ok {
		sess.m.delete(sid)
	}

	return ok
}

func (sess *sessions) valid(sid string) (session, bool) {
	s, ok := sess.m.load(sid)
	if !ok || time.Now().After(s.exp) {
		return session{}, false
	}

	return s, true
}

func (sess *sessions) touch(sid string) bool {
	s, ok := sess.valid(sid)
	if !ok {
		return false
	}

	s.exp = time.Now().Add(s.ttl)

	sess.m.store(sid, s)

	return true
}

func (sess *sessions) periodicCompact(ctx context.Context, interval time.Duration) {
	sess.m.periodicCompact(ctx, interval)
}

func newLoginHandler(password string, ttl time.Duration, sess *sessions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

		pass, err := readPassword(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if subtle.ConstantTimeCompare([]byte(pass), []byte(password)) != 1 {
			time.Sleep(350 * time.Millisecond) // delay to reduce timing/bruteforce signal
			http.Error(w, "unauthorized", http.StatusUnauthorized)

			return
		}

		sid, s, err := sess.login(ttl)
		if err != nil {
			http.Error(w, "internal", http.StatusInternalServerError)
			return
		}

		setSessionCookies(w, sid, s.csrf, s.ttl)

		w.WriteHeader(http.StatusNoContent)
	})
}

var errMissingPassword = errors.New("missing password")

func readPassword(r *http.Request) (string, error) {
	contentType := r.Header.Get("Content-Type")

	mediatype, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}

	switch mediatype {
	case "application/x-www-form-urlencoded", "multipart/form-data", "":
		if err := r.ParseForm(); err != nil {
			return "", fmt.Errorf("read form password: %w", err)
		}

		p := r.Form.Get("password")
		if p == "" {
			return "", errMissingPassword
		}

		return p, nil

	case "application/json":
		var body struct {
			Password string `json:"password"`
		}

		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return "", fmt.Errorf("read json password: %w", err)
		}

		if body.Password == "" {
			return "", errMissingPassword
		}

		return body.Password, nil

	default:
		return "", fmt.Errorf("unsupported content-type: %s", contentType)
	}
}

func setSessionCookies(w http.ResponseWriter, sid, csrf string, ttl time.Duration) {
	maxAge := int(ttl.Seconds())

	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    sid,
		Path:     "/",
		MaxAge:   maxAge,
		SameSite: http.SameSiteStrictMode,
		Secure:   true,
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf",
		Value:    csrf,
		Path:     "/",
		MaxAge:   maxAge,
		SameSite: http.SameSiteStrictMode,
		Secure:   true,
	})
}

func newLogoutHandler(sess *sessions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sidCookie, err := r.Cookie("sid")
		if err == nil && sidCookie.Value != "" {
			sess.logout(sidCookie.Value)
		}

		expireCookie := func(name string) {
			http.SetCookie(w, &http.Cookie{
				Name:     name,
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				SameSite: http.SameSiteStrictMode,
				Secure:   true,
				HttpOnly: name == "sid",
			})
		}

		expireCookie("sid")
		expireCookie("csrf")

		w.WriteHeader(http.StatusNoContent)
	})
}

func newMeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
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

func newAPIRoutes(ctx context.Context, sess *sessions, cancelableJobs *safeMap[string, func()], password string, ttl time.Duration) *http.ServeMux {
	mux := http.NewServeMux()

	for _, e := range config.Endpoints {
		h := newExecHandler(ctx, e, cancelableJobs)

		pattern := fmt.Sprintf(
			"%s %s",
			strings.ToUpper(e.method),
			e.path,
		)

		mux.Handle(pattern, chain(h,
			withSecurityHeaders,
			withAuth(password, e.NoAuth, sess),
			withMeta,
			withTracing,
		))
	}

	mux.Handle("POST /login", chain(newLoginHandler(password, ttl, sess),
		withSecurityHeaders,
		withMeta,
		withTracing,
	))

	mux.Handle("POST /logout", chain(newLogoutHandler(sess),
		withSecurityHeaders,
		withAuth(password, false, sess),
		withMeta,
		withTracing,
	))

	mux.Handle("GET /me", chain(newMeHandler(),
		withSecurityHeaders,
		withAuth(password, false, sess),
		withMeta,
		withTracing,
	))

	mux.Handle("GET /jobs/{id}", chain(newJobHandler(ctx, cancelableJobs),
		withSecurityHeaders,
		withAuth(password, false, sess),
		withMeta,
		withTracing,
	))

	mux.Handle("GET /jobs", chain(newJobsHandler(),
		withSecurityHeaders,
		withAuth(password, false, sess),
		withMeta,
		withTracing,
	))

	mux.Handle("GET /user-routes", chain(newUserRoutesHandler(append(internalEndpoints, config.Endpoints...)),
		withSecurityHeaders,
		withAuth(password, false, sess),
		withMeta,
		withTracing,
	))

	return mux
}
