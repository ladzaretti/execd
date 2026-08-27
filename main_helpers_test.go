package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
)

const (
	testPassword    = "test-password"
	sqliteMemFormat = "file:%s?mode=memory&cache=shared"
)

func newTestApp(t *testing.T, config *Config) (http.Handler, *sync.WaitGroup) {
	t.Helper()

	if err := config.validate(); err != nil {
		t.Fatalf("validate config: %v", err)
	}

	if err := config.resolve(); err != nil {
		t.Fatalf("resolve config: %v", err)
	}

	config.complete()

	database, err := newExecDB(testDatabaseDSN(t.Name()))
	if err != nil {
		t.Fatalf("open in-memory database: %v", err)
	}

	workers := &sync.WaitGroup{}

	t.Cleanup(func() {
		workers.Wait()

		if err := database.close(); err != nil {
			t.Errorf("close in-memory database: %v", err)
		}
	})

	app := &api{
		config:   config,
		requests: database,
	}
	handler := app.newHandler(t.Context(), workers, newSafeMap[string, func()]())

	return handler, workers
}

func testConfig(endpoints ...Endpoint) *Config {
	return &Config{
		Server: Server{
			ListenAddr: "127.0.0.1:0",
			Password:   testPassword,
		},
		Endpoints: endpoints,
		sha:       "test-sha",
	}
}

func testDatabaseDSN(testName string) string {
	return fmt.Sprintf(sqliteMemFormat, url.PathEscape(testName))
}

func requireStatusCode(t *testing.T, response *httptest.ResponseRecorder, want int) {
	t.Helper()

	if got := response.Code; got != want {
		t.Fatalf("got response status %d, want %d; body: %s", got, want, response.Body.String())
	}
}

func mustDecodeJSON(t *testing.T, response *httptest.ResponseRecorder, dst any) {
	t.Helper()

	if err := json.NewDecoder(response.Body).Decode(dst); err != nil {
		t.Fatalf("decode JSON response: %v", err)
	}
}
