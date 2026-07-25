#!/bin/sh
# Trockenlauf des gesamten Mess-Kits OHNE Geraet.
#
# Prueft: Syntax aller Skripte, Vorpruefung (bestanden und absichtlich
# gerissen), Laufstart, Laufende inkl. History-Umsetzung und Auswertung.
# Datenquelle ist der synthetische adb-Ersatz in testdata/fake-adb/.
#
# Das ersetzt KEINE Messung. Es belegt nur, dass die Werkzeugkette laeuft.
#
# Aufruf:  sh tools/smoke-test.sh
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
TMP="${TMPDIR:-/tmp}/s5-smoke-$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

FAILED=0
step() { printf '\n=== %s ===\n' "$1"; }
ok()   { printf '  [ok]   %s\n' "$1"; }
bad()  { printf '  [FEHL] %s\n' "$1"; FAILED=$((FAILED + 1)); }

export ADB="$HERE/testdata/fake-adb/adb"
export S5_SERIAL="127.0.0.1:5555"
export S5_DEVICE_LABEL="DEV-SYN"
chmod +x "$ADB" 2>/dev/null || true

step "1. Syntaxpruefung"
for f in "$HERE"/collect/*.sh "$HERE"/testdata/gen-synthetic.sh "$HERE"/smoke-test.sh; do
  if sh -n "$f"; then ok "$(basename "$f")"; else bad "$(basename "$f")"; fi
done

step "2. Vorpruefung mit gutem Geraetezustand"
if sh "$HERE/collect/s5-precheck.sh" >"$TMP/precheck.log" 2>&1; then
  ok "Vorpruefung bestanden"
else
  bad "Vorpruefung unerwartet gerissen"; cat "$TMP/precheck.log"
fi

step "3. Vorpruefung muss bei falschem Zustand reissen"
if FAKE_PLUGGED=1 FAKE_LEVEL=42 FAKE_SCREEN=true FAKE_THERMAL=2 \
   sh "$HERE/collect/s5-precheck.sh" >"$TMP/precheck-bad.log" 2>&1; then
  bad "Vorpruefung haette reissen muessen"
else
  ok "Vorpruefung erkennt Ladegeraet/Fuellstand/Display/Thermal"
fi

step "4. Lauf starten"
if sh "$HERE/collect/s5-start-run.sh" R3 01 "$TMP/runs" >"$TMP/start.log" 2>&1; then
  ok "s5-start-run.sh"
else
  bad "s5-start-run.sh"; cat "$TMP/start.log"
fi
RUNDIR="$TMP/runs/R3/DEV-SYN-R3-01"
if [ -f "$RUNDIR/run.meta" ]; then ok "run.meta angelegt"; else bad "run.meta fehlt"; fi

step "5. s5-eval bauen"
if cargo build --release --offline --quiet --manifest-path "$HERE/s5-eval/Cargo.toml" 2>"$TMP/build.log"; then
  ok "cargo build"
else
  bad "cargo build"; cat "$TMP/build.log"
fi

step "6. Lauf beenden und auswerten"
# Startzeit zurueckdatieren, damit die Laufdauer plausibel ist.
if [ -f "$RUNDIR/run.meta" ]; then
  NOW=$(date +%s)
  BACK=$((NOW - 86400))
  sed "s/^# start_unix=.*/# start_unix=$BACK/" "$RUNDIR/run.meta" > "$RUNDIR/run.meta.tmp"
  mv "$RUNDIR/run.meta.tmp" "$RUNDIR/run.meta"
fi
if sh "$HERE/collect/s5-end-run.sh" "$RUNDIR" >"$TMP/end.log" 2>&1; then
  ok "s5-end-run.sh"
else
  bad "s5-end-run.sh"; cat "$TMP/end.log"
fi
for f in raw-batterystats-history.txt raw-batterystats-checkin.txt raw-thermalservice.txt samples.csv; do
  if [ -s "$RUNDIR/$f" ]; then ok "$f erzeugt"; else bad "$f fehlt oder leer"; fi
done
if grep -q "Entladerate" "$TMP/end.log"; then ok "Kennzahlen berechnet"; else bad "keine Kennzahlen in der Ausgabe"; fi

step "7. Auswertung ueber die synthetischen Messreihen"
EVAL="$HERE/s5-eval/target/release/s5-eval"
[ -x "$EVAL" ] || EVAL="$HERE/s5-eval/target/release/s5-eval.exe"
if "$EVAL" verdict "$HERE/testdata/synthetic-runs" --allow-synthetic >"$TMP/verdict.log" 2>&1; then
  bad "verdict haette mit Exitcode != 0 enden muessen (K-B ist in den Beispieldaten gerissen)"
else
  rc=$?
  if [ "$rc" = "1" ]; then ok "verdict meldet 'gerissen' (Exit 1) wie erwartet"; else bad "unerwarteter Exitcode $rc"; fi
fi
if grep -q "SYNTHETISCH" "$TMP/verdict.log"; then ok "Synthetik-Warnung ausgegeben"; else bad "Synthetik-Warnung fehlt"; fi

step "8. Thermal-Auswertung"
if "$EVAL" thermal "$HERE/testdata/synthetic-thermalservice.txt" | grep -q "BESTANDEN"; then
  ok "sauberer Dump -> bestanden"
else
  bad "sauberer Dump falsch bewertet"
fi
if "$EVAL" thermal "$HERE/testdata/synthetic-thermalservice-throttled.txt" | grep -q "GERISSEN"; then
  ok "Throttling-Dump -> gerissen"
else
  bad "Throttling nicht erkannt"
fi

printf '\n'
if [ "$FAILED" -eq 0 ]; then
  echo "Trockenlauf vollstaendig bestanden. Das Kit ist einsatzbereit —"
  echo "es fehlen nur Geraete und eine messbare App (siehe VORAUSSETZUNGEN.md)."
  exit 0
fi
echo "$FAILED Pruefung(en) gerissen."
exit 1
