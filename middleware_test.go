package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestWithAuth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                string
		authorization       string
		authEnabled         bool
		wantStatus          int
		wantWWWAuthenticate string
		wantCalled          bool
	}{
		{
			name:                "missing authorization",
			authEnabled:         true,
			wantStatus:          http.StatusUnauthorized,
			wantWWWAuthenticate: "Bearer",
		},
		{
			name:                "invalid authorization scheme",
			authorization:       "Basic test-password",
			authEnabled:         true,
			wantStatus:          http.StatusUnauthorized,
			wantWWWAuthenticate: "Bearer",
		},
		{
			name:                "invalid token",
			authorization:       "Bearer wrong-password",
			authEnabled:         true,
			wantStatus:          http.StatusUnauthorized,
			wantWWWAuthenticate: `Bearer error="invalid_token"`,
		},
		{
			name:          "valid token",
			authorization: "Bearer " + TestPassword,
			authEnabled:   true,
			wantStatus:    http.StatusNoContent,
			wantCalled:    true,
		},
		{
			name:        "authentication disabled",
			authEnabled: false,
			wantStatus:  http.StatusNoContent,
			wantCalled:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			called := false
			handler := withAuth(TestPassword, authEnabled(tt.authEnabled))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true

				w.WriteHeader(http.StatusNoContent)
			}))

			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			request.Header.Set("Authorization", tt.authorization)

			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			RequireStatusCode(t, response, tt.wantStatus)

			if got, want := response.Header().Get("WWW-Authenticate"), tt.wantWWWAuthenticate; got != want {
				t.Errorf("got WWW-Authenticate header %q, want %q", got, want)
			}

			if got, want := called, tt.wantCalled; got != want {
				t.Errorf("got handler called %t, want %t", got, want)
			}
		})
	}
}

func TestWithMeta(t *testing.T) {
	t.Parallel()

	handler := withMeta("test-sha")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	RequireStatusCode(t, response, http.StatusNoContent)

	want := map[string]string{
		"X-Config-Sha":    "test-sha",
		"X-Execd-Version": Version,
	}

	got := make(map[string]string, len(want))
	for header := range want {
		got[header] = response.Header().Get(header)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("metadata headers mismatch (-want +got):\n%s", diff)
	}
}

func TestWithTracingPreservesRequestID(t *testing.T) {
	t.Parallel()

	const requestID = "test-request-id"

	handler := withTracing(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	request.Header.Set("X-Request-Id", requestID)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	RequireStatusCode(t, response, http.StatusNoContent)

	if got, want := response.Header().Get("X-Request-Id"), requestID; got != want {
		t.Errorf("got response request ID %q, want %q", got, want)
	}
}
