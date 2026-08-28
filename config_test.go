package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestConfigValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  *Config
		wantErr string
	}{
		{
			name:   "valid",
			config: NewTestConfig(),
		},
		{
			name: "missing listen address",
			config: &Config{
				Server: Server{Password: TestPassword},
			},
			wantErr: "listen_addr must not be empty",
		},
		{
			name: "missing password",
			config: &Config{
				Server: Server{ListenAddr: "127.0.0.1:0"},
			},
			wantErr: "server password must not be empty",
		},
		{
			name: "invalid listen address",
			config: &Config{
				Server: Server{
					ListenAddr: "not-an-address",
					Password:   TestPassword,
				},
			},
			wantErr: "listen_addr must be host:port or :port",
		},
		{
			name: "invalid log level",
			config: &Config{
				Server: Server{
					ListenAddr: "127.0.0.1:0",
					Password:   TestPassword,
					LogLevel:   "foo",
				},
			},
			wantErr: "invalid log level",
		},
		{
			name: "duplicate endpoint",
			config: NewTestConfig(
				Endpoint{Path: "/ping", Cmd: []string{"echo"}},
				Endpoint{Path: "/ping", Cmd: []string{"echo"}},
			),
			wantErr: "duplicate endpoint: /ping",
		},
		{
			name: "invalid route pattern",
			config: NewTestConfig(Endpoint{
				Path: "/{name...}/tail",
				Cmd:  []string{"echo"},
			}),
			wantErr: "invalid route pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.config.validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("validate config: %v", err)
				}

				return
			}

			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("got validation error %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseFileConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		mode    os.FileMode
		want    *Config
		wantErr string
	}{
		{
			name: "valid config",
			content: `[server]
log_level = "debug"
database_path = "/var/lib/execd/execd.sqlite"
listen_addr = "127.0.0.1:8080"
password = "test-password"
tls = true
cert_file = "/etc/execd/cert.pem"
key_file = "/etc/execd/key.pem"

[[endpoints]]
summary = "Return the configured environment."
path = "/env/{name}"
method = "PUT"
cmd = ["env", "--ignore-environment"]
env_allowlist = ["NAME", "FOO"]
detached = true
uid = 1000
gid = 1001
no_auth = true

[[endpoints]]
path = "/ping"
cmd = ["echo", "pong"]
timeout = "30s"
`,
			mode: 0o600,
			want: &Config{
				Server: Server{
					LogLevel:   "debug",
					DBPath:     "/var/lib/execd/execd.sqlite",
					ListenAddr: "127.0.0.1:8080",
					Password:   "test-password",
					TLS:        true,
					CertFile:   "/etc/execd/cert.pem",
					KeyFile:    "/etc/execd/key.pem",
				},
				Endpoints: []Endpoint{
					{
						Summary:      "Return the configured environment.",
						Path:         "/env/{name}",
						Method:       "PUT",
						Cmd:          []string{"env", "--ignore-environment"},
						EnvAllowlist: []string{"NAME", "FOO"},
						Detached:     true,
						UID:          1000,
						GID:          1001,
						NoAuth:       true,
					},
					{
						Path:    "/ping",
						Cmd:     []string{"echo", "pong"},
						Timeout: "30s",
					},
				},
			},
		},
		{
			name: "unknown field",
			content: `[server]
listen_addr = "127.0.0.1:8080"
password = "test-password"
unknown = true
`,
			mode:    0o600,
			wantErr: `config: unknown fields: "server.unknown"`,
		},
		{
			name: "insecure permissions",
			content: `[server]
listen_addr = "127.0.0.1:8080"
password = "test-password"
`,
			mode:    0o644,
			wantErr: "invalid permissions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "execd.toml")
			if err := os.WriteFile(path, []byte(tt.content), tt.mode); err != nil {
				t.Fatalf("write config file: %v", err)
			}

			if err := os.Chmod(path, tt.mode); err != nil {
				t.Fatalf("set config permissions: %v", err)
			}

			got, err := parseFileConfig(path)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("got parse error %v, want it to contain %q", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("parse config file: %v", err)
			}

			if diff := cmp.Diff(tt.want, got, cmpopts.IgnoreUnexported(Config{}, Endpoint{})); diff != "" {
				t.Errorf("parsed config mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestConfigRedact(t *testing.T) {
	t.Parallel()

	config := &Config{
		Server: Server{
			ListenAddr: "127.0.0.1:8080",
			Password:   "original-password",
		},
		Endpoints: []Endpoint{
			{
				Path: "/ping",
				Cmd:  []string{"echo", "pong"},
			},
		},
	}

	want := &Config{
		Server: Server{
			ListenAddr: "127.0.0.1:8080",
			Password:   redact,
		},
		Endpoints: []Endpoint{
			{
				Path: "/ping",
				Cmd:  []string{"echo", "pong"},
			},
		},
	}

	got := config.redact()

	if diff := cmp.Diff(want, got, cmpopts.IgnoreUnexported(Config{}, Endpoint{})); diff != "" {
		t.Errorf("redacted config mismatch (-want +got):\n%s", diff)
	}
}
