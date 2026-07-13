#!/usr/bin/env bash
# Compatibility wrapper. Use ./yggdrasil.sh for the primary command.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/yggdrasil.sh" "$@"
