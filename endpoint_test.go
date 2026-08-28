package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestEndpointValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		endpoint Endpoint
		wantErr  string
	}{
		{
			name: "valid",
			endpoint: Endpoint{
				Path: "/ping",
				Cmd:  []string{"echo", "pong"},
			},
		},
		{
			name: "empty path",
			endpoint: Endpoint{
				Cmd: []string{"echo"},
			},
			wantErr: "route path is empty",
		},
		{
			name: "unsupported method",
			endpoint: Endpoint{
				Path:   "/ping",
				Method: http.MethodPatch,
				Cmd:    []string{"echo"},
			},
			wantErr: "unsupported method",
		},
		{
			name: "detached endpoint with timeout",
			endpoint: Endpoint{
				Path:     "/ping",
				Cmd:      []string{"echo"},
				Detached: true,
				Timeout:  "1s",
			},
			wantErr: "timeout cannot be used",
		},
		{
			name: "invalid timeout",
			endpoint: Endpoint{
				Path:    "/ping",
				Cmd:     []string{"echo"},
				Timeout: "foo",
			},
			wantErr: "invalid timeout duration",
		},
		{
			name: "path without leading slash",
			endpoint: Endpoint{
				Path: "ping",
				Cmd:  []string{"echo"},
			},
			wantErr: "must start with '/'",
		},
		{
			name: "path with trailing slash",
			endpoint: Endpoint{
				Path: "/ping/",
				Cmd:  []string{"echo"},
			},
			wantErr: "must not end with '/'",
		},
		{
			name: "path with dot segment",
			endpoint: Endpoint{
				Path: "/foo/../ping",
				Cmd:  []string{"echo"},
			},
			wantErr: "must not contain dot segments",
		},
		{
			name: "empty command",
			endpoint: Endpoint{
				Path: "/ping",
			},
			wantErr: "cmd must be a non-empty argv",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.endpoint.validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("validate endpoint: %v", err)
				}

				return
			}

			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("got validation error %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestToEnvKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "lowercase", input: "name", want: "NAME"},
		{name: "camel case", input: "camelCase", want: "CAMEL_CASE"},
		{name: "initial uppercase", input: "Name", want: "NAME"},
		{name: "acronym suffix", input: "apiURL", want: "API_URL"},
		{name: "acronym prefix", input: "URLValue", want: "URL_VALUE"},
		{name: "separator", input: "log-level", want: "LOG_LEVEL"},
		{name: "repeated separators", input: "log__level", want: "LOG_LEVEL"},
		{name: "whitespace separator", input: "log level", want: "LOG_LEVEL"},
		{name: "repeated whitespace", input: "log \t\n level", want: "LOG_LEVEL"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got, want := toEnvKey(tt.input), tt.want; got != want {
				t.Errorf("got environment key %q, want %q", got, want)
			}
		})
	}
}

func TestParamsToEnv(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/exec/env/ada?foo=one&foo=two&camelCase=yes", nil)
	request.SetPathValue("name", "ada")

	got := make(map[string]string)
	for _, value := range paramsToEnv(request, []string{"name"}) {
		key, value, ok := strings.Cut(value, "=")
		if !ok {
			t.Fatalf("parse environment value: got invalid value %q", value)
		}

		got[key] = value
	}

	want := map[string]string{
		"CAMEL_CASE": "yes",
		"FOO":        "one two",
		"NAME":       "ada",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("environment mismatch (-want +got):\n%s", diff)
	}
}

func TestParseInt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		fallback int
		want     int
		wantErr  bool
	}{
		{
			name:     "empty uses fallback",
			fallback: 10,
			want:     10,
		},
		{
			name:  "valid",
			input: "42",
			want:  42,
		},
		{
			name:    "invalid",
			input:   "forty-two",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseInt(tt.input, tt.fallback)
			if tt.wantErr {
				if err == nil {
					t.Error("parse integer: got nil error, want non-nil")
				}

				return
			}

			if err != nil {
				t.Fatalf("parse integer: %v", err)
			}

			if got != tt.want {
				t.Errorf("got integer %d, want %d", got, tt.want)
			}
		})
	}
}

func TestLimitedBuffer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		writes        []string
		wantLength    int
		wantTruncated bool
	}{
		{
			name:       "within limit",
			writes:     []string{"hello"},
			wantLength: len("hello"),
		},
		{
			name:       "at limit",
			writes:     []string{strings.Repeat("a", maxCapturedOutputBytes)},
			wantLength: maxCapturedOutputBytes,
		},
		{
			name:          "over limit",
			writes:        []string{strings.Repeat("a", maxCapturedOutputBytes+1)},
			wantLength:    maxCapturedOutputBytes,
			wantTruncated: true,
		},
		{
			name:          "second write over limit",
			writes:        []string{strings.Repeat("a", maxCapturedOutputBytes), "b"},
			wantLength:    maxCapturedOutputBytes,
			wantTruncated: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buffer limitedBuffer
			for _, input := range tt.writes {
				written, err := buffer.Write([]byte(input))
				if err != nil {
					t.Fatalf("write limited buffer: %v", err)
				}

				if got, want := written, len(input); got != want {
					t.Errorf("got written bytes %d, want %d", got, want)
				}
			}

			if got, want := buffer.Len(), tt.wantLength; got != want {
				t.Errorf("got buffer length %d, want %d", got, want)
			}

			if got, want := buffer.truncated, tt.wantTruncated; got != want {
				t.Errorf("got truncated %t, want %t", got, want)
			}
		})
	}
}
