#!/bin/sh
set -eu
PROJECT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
exec /usr/bin/python3 -I "$PROJECT_DIR/scripts/server-package.py" install "$@"
