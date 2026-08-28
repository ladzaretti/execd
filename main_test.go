package main_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	execd "github.com/ladzaretti/exec"
)

type acceptedJob struct {
	ID       string `json:"id"`
	Location string `json:"location"`
}

func executeEndpoint(t *testing.T, endpoint execd.Endpoint, target string) (acceptedJob, execd.RequestState) {
	t.Helper()

	app := execd.NewTestApp(t, execd.NewTestConfig(endpoint))

	method := endpoint.Method
	if method == "" {
		method = http.MethodPost
	}

	execRequest := httptest.NewRequestWithContext(t.Context(), method, target, nil)
	if !endpoint.NoAuth {
		execRequest.Header.Set("Authorization", "Bearer "+execd.TestPassword)
	}

	execResponse := httptest.NewRecorder()
	app.Handler.ServeHTTP(execResponse, execRequest)

	execd.RequireStatusCode(t, execResponse, http.StatusAccepted)

	var accepted acceptedJob
	execd.MustDecodeJSON(t, execResponse, &accepted)

	app.Wait()

	jobRequest := httptest.NewRequestWithContext(t.Context(), http.MethodGet, accepted.Location, nil)
	jobRequest.Header.Set("Authorization", "Bearer "+execd.TestPassword)

	jobResponse := httptest.NewRecorder()
	app.Handler.ServeHTTP(jobResponse, jobRequest)

	execd.RequireStatusCode(t, jobResponse, http.StatusOK)

	var job execd.RequestState
	execd.MustDecodeJSON(t, jobResponse, &job)

	return accepted, job
}

func handlerExecutesEndpoint(t *testing.T) {
	t.Helper()

	endpoint := execd.Endpoint{
		Path:   "/ping",
		Method: http.MethodGet,
		Cmd:    []string{"/bin/echo", "pong"},
	}
	accepted, job := executeEndpoint(t, endpoint, "/exec/ping")

	if accepted.ID == "" {
		t.Error("response did not include a job ID")
	}

	if got, want := accepted.Location, "/jobs/"+accepted.ID; got != want {
		t.Errorf("got job location %q, want %q", got, want)
	}

	want := execd.RequestState{
		UUID:  accepted.ID,
		Path:  "/exec/ping",
		State: "completed",
		Result: execd.ExecResult{
			Stdout:   "pong\n",
			ExitCode: new(0),
		},
	}
	if diff := cmp.Diff(want, job, cmpopts.IgnoreFields(execd.RequestState{}, "StartedAt", "CompletedAt")); diff != "" {
		t.Errorf("job mismatch (-want +got):\n%s", diff)
	}
}

func handlerNoAuthDoesNotExposeJobAPI(t *testing.T) {
	t.Helper()

	app := execd.NewTestApp(t, execd.NewTestConfig(execd.Endpoint{
		Path:   "/ping",
		Method: http.MethodGet,
		Cmd:    []string{"/bin/echo", "pong"},
		NoAuth: true,
	}))

	execRequest := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/exec/ping", nil)
	execResponse := httptest.NewRecorder()
	app.Handler.ServeHTTP(execResponse, execRequest)

	execd.RequireStatusCode(t, execResponse, http.StatusAccepted)

	for _, target := range []string{"/jobs", "/user-routes"} {
		t.Run(target, func(t *testing.T) {
			t.Parallel()

			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
			response := httptest.NewRecorder()
			app.Handler.ServeHTTP(response, request)

			execd.RequireStatusCode(t, response, http.StatusUnauthorized)
		})
	}
}

func handlerPassesParametersToEndpoint(t *testing.T) {
	t.Helper()

	endpoint := execd.Endpoint{
		Path:   "/env/{name}",
		Method: http.MethodGet,
		Cmd:    []string{"env"},
		NoAuth: true,
	}
	_, job := executeEndpoint(t, endpoint, "/exec/env/ada?foo=one&foo=two&camelCase=yes")

	want := map[string]string{
		"CAMEL_CASE": "yes",
		"FOO":        "one two",
		"NAME":       "ada",
	}

	got := make(map[string]string)
	for line := range strings.SplitSeq(strings.TrimSpace(job.Result.Stdout), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("parse environment output: got invalid line %q", line)
		}

		got[key] = value
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("endpoint environment mismatch (-want +got):\n%s", diff)
	}
}

func handlerPersistsFailedJob(t *testing.T) {
	t.Helper()

	endpoint := execd.Endpoint{
		Path:   "/fail",
		Method: http.MethodGet,
		Cmd:    []string{"/bin/sh", "-c", "printf stdout; printf stderr >&2; exit 7"},
		NoAuth: true,
	}
	accepted, job := executeEndpoint(t, endpoint, "/exec/fail")

	want := execd.RequestState{
		UUID:  accepted.ID,
		Path:  "/exec/fail",
		State: "failed",
		Result: execd.ExecResult{
			Stdout:   "stdout",
			Stderr:   "stderr",
			ExitCode: new(7),
			Error:    "exit status 7",
		},
	}
	if diff := cmp.Diff(want, job,
		cmpopts.IgnoreFields(execd.RequestState{}, "StartedAt", "CompletedAt"),
	); diff != "" {
		t.Errorf("job mismatch (-want +got):\n%s", diff)
	}

	if !strings.Contains(job.Result.Error, "exit status 7") {
		t.Errorf("got job error %q, want it to contain %q", job.Result.Error, "exit status 7")
	}
}

func handlerListsJobs(t *testing.T) {
	t.Helper()

	app := execd.NewTestApp(t, execd.NewTestConfig())
	for _, request := range []struct {
		id    string
		state string
	}{
		{id: "001", state: "canceled"},
		{id: "002", state: "completed"},
		{id: "003", state: "completed"},
		{id: "004", state: "failed"},
	} {
		if _, err := app.Insert(t.Context(), request.id, request.state); err != nil {
			t.Fatalf("insert test request: %v", err)
		}
	}

	tests := []struct {
		name     string
		target   string
		wantCode int
		wantIDs  []string
		wantLink string
	}{
		{
			name:     "first page",
			target:   "/jobs?limit=2",
			wantCode: http.StatusOK,
			wantIDs:  []string{"004", "003"},
			wantLink: `</jobs?cursor=002&limit=2>; rel="next"`,
		},
		{
			name:     "normalized filters",
			target:   "/jobs?filter=COMPLETED,%20failed",
			wantCode: http.StatusOK,
			wantIDs:  []string{"004", "003", "002"},
		},
		{
			name:     "invalid filter",
			target:   "/jobs?filter=unknown",
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "invalid limit",
			target:   "/jobs?limit=0",
			wantCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tt.target, nil)
			request.Header.Set("Authorization", "Bearer "+execd.TestPassword)

			response := httptest.NewRecorder()
			app.Handler.ServeHTTP(response, request)

			execd.RequireStatusCode(t, response, tt.wantCode)

			if tt.wantCode != http.StatusOK {
				return
			}

			var jobs []struct {
				ID string `json:"id"`
			}
			execd.MustDecodeJSON(t, response, &jobs)

			gotIDs := make([]string, len(jobs))
			for i, job := range jobs {
				gotIDs[i] = job.ID
			}

			if diff := cmp.Diff(tt.wantIDs, gotIDs); diff != "" {
				t.Errorf("job IDs mismatch (-want +got):\n%s", diff)
			}

			if got, want := response.Header().Get("Link"), tt.wantLink; got != want {
				t.Errorf("got Link header %q, want %q", got, want)
			}
		})
	}
}

func handlerCancelsJob(t *testing.T) {
	t.Helper()

	app := execd.NewTestApp(t, execd.NewTestConfig(execd.Endpoint{
		Path:   "/wait",
		Method: http.MethodGet,
		Cmd:    []string{"/bin/sleep", "30"},
		NoAuth: true,
	}))

	execRequest := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/exec/wait", nil)
	execResponse := httptest.NewRecorder()
	app.Handler.ServeHTTP(execResponse, execRequest)

	execd.RequireStatusCode(t, execResponse, http.StatusAccepted)

	var accepted acceptedJob
	execd.MustDecodeJSON(t, execResponse, &accepted)

	getJob := func() execd.RequestState {
		request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, accepted.Location, nil)
		request.Header.Set("Authorization", "Bearer "+execd.TestPassword)

		response := httptest.NewRecorder()
		app.Handler.ServeHTTP(response, request)

		execd.RequireStatusCode(t, response, http.StatusOK)

		var job execd.RequestState
		execd.MustDecodeJSON(t, response, &job)

		return job
	}

	timeout := time.NewTimer(time.Second)
	defer timeout.Stop()

	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()

	for getJob().State != "running" {
		select {
		case <-timeout.C:
			t.Fatalf("wait for job state: got no job in running state within %s", time.Second)
		case <-ticker.C:
		}
	}

	cancelRequest := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, accepted.Location, nil)
	cancelRequest.Header.Set("Authorization", "Bearer "+execd.TestPassword)

	cancelResponse := httptest.NewRecorder()
	app.Handler.ServeHTTP(cancelResponse, cancelRequest)

	execd.RequireStatusCode(t, cancelResponse, http.StatusNoContent)

	app.Wait()

	if got, want := string(getJob().State), "canceled"; got != want {
		t.Errorf("got job state %q, want %q", got, want)
	}
}

func handlerPersistsTimedOutJob(t *testing.T) {
	t.Helper()

	endpoint := execd.Endpoint{
		Path:    "/timeout",
		Method:  http.MethodGet,
		Cmd:     []string{"/bin/sleep", "1"},
		Timeout: "1ms",
		NoAuth:  true,
	}
	_, job := executeEndpoint(t, endpoint, "/exec/timeout")

	if got, want := string(job.State), "failed"; got != want {
		t.Errorf("got job state %q, want %q", got, want)
	}
}

func handlerJobMethods(t *testing.T) {
	t.Helper()

	app := execd.NewTestApp(t, execd.NewTestConfig())

	tests := []struct {
		name      string
		method    string
		wantCode  int
		wantAllow string
	}{
		{
			name:     "get unknown job",
			method:   http.MethodGet,
			wantCode: http.StatusNotFound,
		},
		{
			name:      "delete unknown job",
			method:    http.MethodDelete,
			wantCode:  http.StatusNotFound,
			wantAllow: "",
		},
		{
			name:      "unsupported method",
			method:    http.MethodPost,
			wantCode:  http.StatusMethodNotAllowed,
			wantAllow: "GET, DELETE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			request := httptest.NewRequestWithContext(t.Context(), tt.method, "/jobs/unknown", nil)
			request.Header.Set("Authorization", "Bearer "+execd.TestPassword)

			response := httptest.NewRecorder()
			app.Handler.ServeHTTP(response, request)

			execd.RequireStatusCode(t, response, tt.wantCode)

			if got, want := response.Header().Get("Allow"), tt.wantAllow; got != want {
				t.Errorf("got Allow header %q, want %q", got, want)
			}
		})
	}
}

func handlerListsRoutes(t *testing.T) {
	t.Helper()

	type userRoute struct {
		Summary string   `json:"summary"`
		Path    string   `json:"path"`
		Cmd     []string `json:"cmd"`
		Timeout string   `json:"timeout"`
		Auth    bool     `json:"requires_auth"`
	}

	app := execd.NewTestApp(t, execd.NewTestConfig(
		execd.Endpoint{
			Summary: "Public endpoint.",
			Path:    "/public",
			Method:  http.MethodGet,
			Cmd:     []string{"/bin/echo", "public"},
			NoAuth:  true,
		},
		execd.Endpoint{
			Summary: "Protected endpoint.",
			Path:    "/protected",
			Cmd:     []string{"/bin/echo", "protected"},
			Timeout: "1s",
		},
	))

	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/user-routes", nil)
	request.Header.Set("Authorization", "Bearer "+execd.TestPassword)

	response := httptest.NewRecorder()
	app.Handler.ServeHTTP(response, request)

	execd.RequireStatusCode(t, response, http.StatusOK)

	var got []userRoute
	execd.MustDecodeJSON(t, response, &got)

	want := []userRoute{
		{
			Summary: "Retrieve job details by ID.",
			Path:    "GET /jobs/{id}",
			Auth:    true,
		},
		{
			Summary: "List recently completed jobs.",
			Path:    "GET /jobs",
			Auth:    true,
		},
		{
			Summary: "List all user defined execution routes.",
			Path:    "GET /user-routes",
			Auth:    true,
		},
		{
			Summary: "Public endpoint.",
			Path:    "GET /exec/public",
			Cmd:     []string{"/bin/echo", "public"},
			Auth:    false,
		},
		{
			Summary: "Protected endpoint.",
			Path:    "POST /exec/protected",
			Cmd:     []string{"/bin/echo", "protected"},
			Timeout: "1s",
			Auth:    true,
		},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("routes mismatch (-want +got):\n%s", diff)
	}
}

func TestHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{name: "executes endpoint", test: handlerExecutesEndpoint},
		{name: "does not expose job API in no-auth mode", test: handlerNoAuthDoesNotExposeJobAPI},
		{name: "passes parameters to endpoint", test: handlerPassesParametersToEndpoint},
		{name: "persists failed job", test: handlerPersistsFailedJob},
		{name: "lists jobs", test: handlerListsJobs},
		{name: "cancels job", test: handlerCancelsJob},
		{name: "persists timed out job", test: handlerPersistsTimedOutJob},
		{name: "handles job methods", test: handlerJobMethods},
		{name: "lists routes", test: handlerListsRoutes},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tt.test(t)
		})
	}
}
