package main

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestHandleSubcommandVersion(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer

	handled, err := handleSubcommand([]string{"version"}, &output)
	if err != nil {
		t.Fatalf("handle version subcommand: %v", err)
	}

	if !handled {
		t.Fatal("version subcommand was not handled")
	}

	if got, want := output.String(), Version+"\n"; got != want {
		t.Errorf("got version output %q, want %q", got, want)
	}
}

func TestHandleSubcommandConfigGenerate(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer

	handled, err := handleSubcommand([]string{"config", "generate"}, &output)
	if err != nil {
		t.Fatalf("handle config generate subcommand: %v", err)
	}

	if !handled {
		t.Fatal("config generate subcommand was not handled")
	}

	want := `[server]
# Log level (default: info).
# log_level = ''
# SQLite database path (default: XDG cache directory/.execd.d/execd.sqlite).
# database_path = ''
# Bearer token for protected endpoints (required).
password = ''
# Listen address (required).
listen_addr = ':8443'
# Enable TLS.
# tls = false
# TLS certificate file (required when tls is true).
# cert_file = ''
# TLS private key file (required when tls is true).
# key_file = ''

[[endpoints]]
# Human-readable route description.
summary = 'Health check.'
# Route path below /exec (required).
path = '/ping'
# HTTP method (default: POST).
method = 'GET'
# Fixed command and arguments (required).
cmd = ['/usr/bin/echo', 'pong']
# Environment variables inherited from execd.
# env_allowlist = []
# Start without waiting for completion.
# detached = false
# UID to run as (requires execd to run as root).
# uid = 0
# GID to run as (requires execd to run as root).
# gid = 0
# Maximum execution time as a Go duration (for example: 30s, 5m); not available for detached commands.
# timeout = ''
# Disable authentication for this execution route.
# no_auth = false
`
	if diff := cmp.Diff(want, output.String()); diff != "" {
		t.Errorf("generated config mismatch (-want +got):\n%s", diff)
	}
}

func TestHandleSubcommandUnknown(t *testing.T) {
	t.Parallel()

	handled, err := handleSubcommand([]string{"unknown"}, new(bytes.Buffer))
	if handled {
		t.Error("unknown subcommand was handled")
	}

	if err == nil {
		t.Fatal("unknown subcommand error = nil")
	}

	if got, want := err.Error(), "unknown command: unknown"; got != want {
		t.Errorf("got error %q, want %q", got, want)
	}
}
