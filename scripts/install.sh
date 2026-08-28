#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR=/usr/local/bin

check_sudo() {
    if [[ "$EUID" == 0 ]]; then
        echo "error: do not run as root (sudo will be used when needed)" >&2
        exit 1
    fi
}

check_files() {
    echo "validating release files..."

    local ok=true

    if [[ ! -x "$SCRIPT_DIR/execd" ]]; then
        echo "error: execd is not executable at $SCRIPT_DIR" >&2
        ok=false
    fi

    if [[ -L "$INSTALL_DIR/execd" ]]; then
        echo "error: $INSTALL_DIR/execd is a symlink; refusing to overwrite" >&2
        ok=false
    fi

    if [[ $ok == false ]]; then
        exit 1
    fi

    echo "OK."
}

check_sudo
check_files

sudo -k

echo "installing execd to $INSTALL_DIR"
sudo install -m 0755 "$SCRIPT_DIR/execd" "$INSTALL_DIR/execd.new"
sudo mv -f "$INSTALL_DIR/execd.new" "$INSTALL_DIR/execd"
echo "OK."
