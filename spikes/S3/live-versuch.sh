#!/usr/bin/env bash
# Spike S3 — fuehrt die Ende-zu-Ende-Messung aus und protokolliert sie.
#
# Aufruf: bash spikes/S3/live-versuch.sh [VARIANTE] [BEOBACHTUNG_S] [SONDE_S] [BOOT_TIMEOUT_S]
# Standard: ab 900 15 420
set -u

cd "$(dirname "$0")/s3-live" || exit 1
mkdir -p ../ergebnisse
OUT="../ergebnisse/T-live-versuch.txt"

VAR="${1:-ab}"
BEOB="${2:-900}"
SONDE="${3:-15}"
BOOT="${4:-420}"

{
  echo "# Spike S3 — Ende-zu-Ende-Versuch"
  echo "# Start: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# Argumente: $VAR $BEOB $SONDE $BOOT"
  echo "# rustc: $(rustc -V)"
  echo
} > "$OUT"

RUST_LOG="${RUST_LOG:-info}" ./target/release/revocation-latency.exe "$VAR" "$BEOB" "$SONDE" "$BOOT" >> "$OUT" 2>&1
RC=$?

{
  echo
  echo "# Exitcode: $RC"
  echo "# Ende: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >> "$OUT"
exit $RC
