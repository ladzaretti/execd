# execd - Expose configured commands as HTTP endpoints.

[![GitHub release](https://img.shields.io/github/v/release/ladzaretti/execd)](https://github.com/ladzaretti/execd/releases)
![status: beta](https://img.shields.io/badge/status-beta-yellow)
![license](https://img.shields.io/github/license/ladzaretti/execd)

`execd` is a small self-hosted daemon for triggering explicitly configured commands over HTTP and inspecting their job history. It is intended for private homelabs and trusted callers—not direct public-internet exposure.

## Installation

### Go install

```bash
go install github.com/ladzaretti/execd@latest
```

### Build from source

```bash
git clone https://github.com/ladzaretti/execd.git
cd execd
make build
```

The binary is written to `bin/execd`.

## Configuration

By default, execd reads `~/.config/.execd.toml`. The configuration file must have `0600` permissions.

Generate a starting point, set a real password, and add or replace endpoints:

```bash
mkdir -p ~/.config
execd config generate > ~/.config/.execd.toml
chmod 600 ~/.config/.execd.toml
```

```toml
{{CONFIG}}
```

Configured paths are mounted below `/exec`. A missing `method` defaults to `POST`. `no_auth` makes only that execution endpoint public; job and route APIs always require the server password.

`env_allowlist` copies selected variables from execd's environment. Path and query parameters are also passed to the command as upper-snake-case environment variables: `POST /exec/backup/home?dryRun=true` supplies `NAME=home` and `DRY_RUN=true`.

## Usage

```console
$ execd -h
{{USAGE}}
```

Start it with a config file:

```bash
execd -config /etc/execd.toml
```

Trigger a protected endpoint and inspect its asynchronous job:

```bash
curl -H 'Authorization: Bearer change-me' \
  http://localhost:8443/exec/ping

curl -H 'Authorization: Bearer change-me' \
  http://localhost:8443/jobs/<job-id>
```

The execution request returns `202 Accepted` with a job ID and relative job location. Jobs can be listed with `GET /jobs`, inspected with `GET /jobs/{id}`, canceled with `DELETE /jobs/{id}`, and configured routes discovered with `GET /user-routes`.

## Security

Keep execd on a private network and use a strong server password. Commands and their argv are fixed in configuration, but request path/query parameters become command environment variables; treat callers as trusted and validate values in the invoked command when appropriate.
