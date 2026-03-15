#!/bin/bash
# Shared helpers for relay deployment scripts.
#
# This file is intended to be sourced, not executed.

get_generic_pass() {
  # Best-effort: extract password from a markdown snippet like: `root / PASSWORD`.
  # Caller must set PASS_MD.
  if [ -z "${PASS_MD:-}" ] || [ ! -f "$PASS_MD" ]; then
    return 1
  fi
  sed -n 's/.*`root \/ \([^`]*\)`.*/\1/p' "$PASS_MD" | head -n1
}

