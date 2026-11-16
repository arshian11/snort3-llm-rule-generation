#!/usr/bin/env bash
#
# test.sh — Backward-compatible wrapper for demo.sh
# Please use ./demo.sh directly.
#

exec "$(dirname "${BASH_SOURCE[0]}")/demo.sh" "$@"
