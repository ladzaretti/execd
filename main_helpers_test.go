package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
)

const (
	TestPassword    = "test-password"
	sqliteMemFormat = "file:%s?mode=memory&cache=shared"
)

type TestApp struct {
	Handler  http.Handler
	requests *requestStore
	workers  *sync.WaitGroup
}

func NewTestApp(t *testing.T, config *Config) *TestApp {
	t.Helper()

	if err := config.validate(); err != nil {
		t.Fatalf("validate config: %v", err)
	}

	if err := config.resolve(); err != nil {
		t.Fatalf("resolve config: %v", err)
	}

	config.complete()

	database := NewTestRequestStore(t)

	workers := &sync.WaitGroup{}

	t.Cleanup(func() {
		workers.Wait()
	})

	app := &api{
		config:   config,
		requests: database,
	}
	handler := app.newHandler(t.Context(), workers, newSafeMap[string, func()]())

	return &TestApp{
		Handler:  handler,
		requests: database,
		workers:  workers,
	}
}

func NewTestConfig(endpoints ...Endpoint) *Config {
	return &Config{
		Server: Server{
			ListenAddr: "127.0.0.1:0",
			Password:   TestPassword,
		},
		Endpoints: endpoints,
		sha:       "test-sha",
	}
}

func MemoryDatabaseDSN(testName string) string {
	return fmt.Sprintf(sqliteMemFormat, url.PathEscape(testName))
}

func NewTestRequestStore(t *testing.T) *requestStore {
	t.Helper()

	database, err := newExecDB(MemoryDatabaseDSN(t.Name()))
	if err != nil {
		t.Fatalf("open in-memory database: %v", err)
	}

	t.Cleanup(func() {
		if err := database.close(); err != nil {
			t.Errorf("close in-memory database: %v", err)
		}
	})

	return database
}

func (a *TestApp) Wait() { a.workers.Wait() }

func (a *TestApp) Insert(ctx context.Context, id, state string) (int, error) {
	return a.requests.insert(ctx, id, RequestState{
		Path:  "/exec/ping",
		State: execState(state),
	})
}

func RequireStatusCode(t *testing.T, response *httptest.ResponseRecorder, wantStatus int) {
	t.Helper()

	if got, want := response.Code, wantStatus; got != want {
		t.Fatalf("got response status %d, want %d; body: %s", got, want, response.Body.String())
	}
}

func MustDecodeJSON(t *testing.T, response *httptest.ResponseRecorder, dst any) {
	t.Helper()

	if err := json.NewDecoder(response.Body).Decode(dst); err != nil {
		t.Fatalf("decode JSON response: %v", err)
	}
}
