#!/bin/sh
set -e

# Source environment file if it exists (startup script can write env vars here)
OIDC_ENV_FILE="${OIDC_ENV_FILE:-/etc/oidc-client.env}"
if [ -f "$OIDC_ENV_FILE" ]; then
  echo "[entrypoint] Sourcing $OIDC_ENV_FILE"
  # shellcheck disable=SC1090
  . "$OIDC_ENV_FILE"
fi

# Run startup script if provided (sourced so env vars propagate)
STARTUP_SCRIPT="${STARTUP_SCRIPT:-/startup.sh}"
if [ -f "$STARTUP_SCRIPT" ]; then
  echo "[entrypoint] Running startup script: $STARTUP_SCRIPT"
  # shellcheck disable=SC1090
  . "$STARTUP_SCRIPT"
fi

exec "$@"
