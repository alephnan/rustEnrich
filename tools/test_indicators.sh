#!/usr/bin/env bash
# Keep shell tracing away from the client and its credentials.
set +x
set -euo pipefail

if ! command -v python3 >/dev/null; then
    printf 'Python 3 is required. On Arch: sudo pacman -S python\n' >&2
    exit 2
fi
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec python3 "$script_dir/smoke_client.py" "$@"
