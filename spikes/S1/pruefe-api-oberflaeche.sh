#!/usr/bin/env bash
# Spike S1 — reproduziert die API-Oberflaechen-Messung.
#
# Erwartetes Ergebnis:
#   1. Service-Seite (Restricted Discovery) uebersetzt OHNE `experimental-api`
#   2. Client-seitige Schluesselverwaltung uebersetzt NICHT ohne `experimental-api`
#
# Aufruf:  bash spikes/S1/pruefe-api-oberflaeche.sh
set -u

cd "$(dirname "$0")/api-nonexp" || exit 1
OUT="../ergebnisse/T-api-oberflaeche.txt"
mkdir -p ../ergebnisse

{
  echo "# Spike S1 — API-Oberflaeche arti-client 0.44.0 ohne experimental-api"
  echo "# $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# rustc: $(rustc -V)"
  echo
} > "$OUT"

echo "[1] cargo check (Service-Seite, ohne experimental-api)" | tee -a "$OUT"
if cargo check --quiet 2>>"$OUT"; then
  echo "    Ergebnis: uebersetzt -> Restricted Discovery service-seitig nicht-experimentell" | tee -a "$OUT"
  R1=0
else
  echo "    Ergebnis: FEHLGESCHLAGEN" | tee -a "$OUT"
  R1=1
fi
echo | tee -a "$OUT"

echo "[2] cargo check --features client-key-api (Client-Seite, ohne experimental-api)" | tee -a "$OUT"
if cargo check --quiet --features client-key-api 2>>"$OUT"; then
  echo "    Ergebnis: uebersetzt -> Client-Seite waere nicht-experimentell" | tee -a "$OUT"
  R2=0
else
  echo "    Ergebnis: uebersetzt NICHT -> generate/insert/rotate/remove_service_discovery_key" | tee -a "$OUT"
  echo "              liegen hinter dem Feature experimental-api" | tee -a "$OUT"
  R2=1
fi
echo | tee -a "$OUT"

echo "Erwartung: [1] uebersetzt, [2] uebersetzt nicht." | tee -a "$OUT"
if [ "$R1" -eq 0 ] && [ "$R2" -eq 1 ]; then
  echo "GESAMT: wie erwartet" | tee -a "$OUT"
  exit 0
fi
echo "GESAMT: ABWEICHUNG — Befund im Bericht pruefen" | tee -a "$OUT"
exit 1
