#!/usr/bin/env bash
# Spike S3 — misst per Compilerlauf, welche Hebel arti 0.44.0 fuer die
# erzwungene Intro-Point-Rotation (ADR-15, spec/protokoll-spec.md §11) bietet.
#
# Aufruf:  bash spikes/S3/pruefe-rotations-api.sh
set -u

cd "$(dirname "$0")/rotations-api" || exit 1
OUT="../ergebnisse/T-rotations-api.txt"
mkdir -p ../ergebnisse

{
  echo "# Spike S3 — Hebel fuer erzwungene Intro-Point-Rotation, arti 0.44.0"
  echo "# $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# rustc: $(rustc -V)"
  echo "# ohne Feature experimental-api, kein Netzverkehr"
  echo
} > "$OUT"

lauf() {
  local name="$1"; shift
  local erwartung="$1"; shift
  echo "== $name (Erwartung: $erwartung) ==" | tee -a "$OUT"
  local start end
  start=$(date +%s)
  if cargo check --quiet "$@" >>"$OUT" 2>&1; then
    end=$(date +%s)
    echo "   uebersetzt (${erwartung}) — Dauer $((end-start)) s" | tee -a "$OUT"
    echo "   ERGEBNIS: VORHANDEN" | tee -a "$OUT"
    RES="VORHANDEN"
  else
    end=$(date +%s)
    echo "   uebersetzt NICHT — Dauer $((end-start)) s" | tee -a "$OUT"
    echo "   ERGEBNIS: NICHT VORHANDEN" | tee -a "$OUT"
    RES="NICHT VORHANDEN"
  fi
  echo | tee -a "$OUT"
}

lauf "L1 reconfigure (Clientliste verkleinern)" "vorhanden"
L1="$RES"
lauf "L2 pause() (Dienst anhalten)" "nicht vorhanden" --features probe-pause
L2="$RES"
lauf "L3 rotate_intro_points()" "nicht vorhanden" --features probe-rotate
L3="$RES"
lauf "L4 drop + launch_onion_service (Neustart)" "vorhanden" --features probe-relaunch
L4="$RES"
lauf "C1 Rotationsbestaetigung aus OnionServiceStatus" "nicht vorhanden" --features probe-confirm
C1="$RES"

{
  echo "== Zusammenfassung =="
  echo "L1 reconfigure (Clientliste)          : $L1"
  echo "L2 pause()                            : $L2"
  echo "L3 rotate_intro_points()              : $L3"
  echo "L4 drop + relaunch                    : $L4"
  echo "C1 Rotation bestaetigbar (Status-API) : $C1"
} | tee -a "$OUT"
