#!/bin/sh
# Beendet einen S5-Messlauf: Rohdaten einsammeln, Fuellstandskurve aus der
# Geraete-History rekonstruieren, Kennzahlen ausgeben.
#
# Aufruf:  S5_SERIAL=... S5_DEVICE_LABEL=DEV-A sh s5-end-run.sh <laufverzeichnis>
#
# Erzeugt im Laufverzeichnis:
#   raw-batterystats-history.txt   dumpsys batterystats --history
#   raw-batterystats-checkin.txt   dumpsys batterystats --checkin
#   raw-thermalservice.txt         dumpsys thermalservice (Endzustand)
#   raw-battery.txt                dumpsys battery
#   samples.csv                    Fuellstandskurve im Sample-CSV-Format
#   run.meta                       um Endwerte ergaenzt
#
# Optional (nur mit S5_BUGREPORT=1): bugreport.zip fuer Battery Historian.
# ACHTUNG: Ein Bugreport enthaelt sehr viel Geraetekontext (Paketnamen, WLAN,
# Logs). Er bleibt lokal, wird nicht ins Repo gelegt und nicht weitergegeben
# (CLAUDE.md: keine Schluessel/Adressen/Kontakt-IDs nach aussen, ADR-14).

. "$(dirname "$0")/_common.sh"

RUNDIR="${1:-}"
[ -n "$RUNDIR" ] || die "Aufruf: s5-end-run.sh <laufverzeichnis>"
[ -d "$RUNDIR" ] || die "$RUNDIR ist kein Verzeichnis"
[ -f "$RUNDIR/run.meta" ] || die "$RUNDIR/run.meta fehlt — kein gestarteter Lauf"

need_device

START=$(awk -F= '/^# start_unix=/{print $2}' "$RUNDIR/run.meta")
SERIES=$(awk -F= '/^# series=/{print $2}' "$RUNDIR/run.meta")
DEVICE=$(awk -F= '/^# device=/{print $2}' "$RUNDIR/run.meta")
END=$(now_unix)
DUR=$((END - START))
info "Lauf $SERIES ($DEVICE): Dauer $((DUR / 3600)) h $(((DUR % 3600) / 60)) min"
if [ "$DUR" -lt 72000 ]; then
  warn "Lauf kuerzer als 20 h — nach MESSPROTOKOLL.md §4 nicht Gate-tauglich."
fi

plugged=$(battery_plugged)
[ "$plugged" = "0" ] || warn "Geraet ist am Ladegeraet — Lauf ist verfaelscht, wenn das waehrend des Laufs passierte."

info "Rohdaten holen ..."
sh_ dumpsys batterystats --history > "$RUNDIR/raw-batterystats-history.txt" 2>/dev/null || \
  warn "history-Dump fehlgeschlagen"
sh_ dumpsys batterystats --checkin > "$RUNDIR/raw-batterystats-checkin.txt" 2>/dev/null || \
  warn "checkin-Dump fehlgeschlagen"
sh_ dumpsys thermalservice > "$RUNDIR/raw-thermalservice.txt" 2>/dev/null || \
  warn "thermalservice-Dump fehlgeschlagen"
sh_ dumpsys battery > "$RUNDIR/raw-battery.txt" 2>/dev/null || true
sh_ dumpsys deviceidle > "$RUNDIR/raw-deviceidle.txt" 2>/dev/null || true

{
  echo "# end_unix=$END"
  echo "# duration_s=$DUR"
  echo "# end_level=$(battery_level)"
  echo "# end_charge_uah=$(battery_counter)"
  echo "# end_temp_dc=$(battery_temp_dc)"
  echo "# end_thermal=$(thermal_status)"
  echo "# end_plugged=$plugged"
} >> "$RUNDIR/run.meta"

if [ "${S5_BUGREPORT:-0}" = "1" ]; then
  info "Bugreport (fuer Battery Historian) — kann einige Minuten dauern ..."
  adb_ bugreport "$RUNDIR/bugreport.zip" || warn "bugreport fehlgeschlagen"
  info "Battery Historian:  docker run -p 9999:9999 gcr.io/android-battery-historian/stable:3.0 --port 9999"
  info "Dann $RUNDIR/bugreport.zip im Browser hochladen (lokal, kein Upload nach aussen)."
fi

# --- Fuellstandskurve rekonstruieren ---------------------------------------
EVAL_BIN="${S5_EVAL_BIN:-}"
if [ -z "$EVAL_BIN" ]; then
  for cand in \
    "$(dirname "$0")/../s5-eval/target/release/s5-eval" \
    "$(dirname "$0")/../s5-eval/target/debug/s5-eval" \
    "$(dirname "$0")/../s5-eval/target/release/s5-eval.exe" \
    "$(dirname "$0")/../s5-eval/target/debug/s5-eval.exe"; do
    if [ -x "$cand" ]; then EVAL_BIN="$cand"; break; fi
  done
fi
if [ -z "$EVAL_BIN" ]; then
  warn "s5-eval nicht gebaut. Bauen mit:  cargo build --release --manifest-path $(dirname "$0")/../s5-eval/Cargo.toml"
  warn "Rohdaten sind gesichert; samples.csv muss danach erzeugt werden."
  exit 0
fi

"$EVAL_BIN" history "$RUNDIR/raw-batterystats-history.txt" \
  --series "$SERIES" --device "$DEVICE" --start-unix "$START" \
  --out "$RUNDIR/samples.csv" || {
    warn "History-Umsetzung fehlgeschlagen. Format pruefen:"
    warn "  head -20 $RUNDIR/raw-batterystats-history.txt"
    warn "  ggf. '$EVAL_BIN history ... --deltas' versuchen"
    exit 1
  }

# Metadaten aus run.meta in die Sample-Datei uebernehmen (design_capacity_uah usw.)
awk '/^# /{print}' "$RUNDIR/run.meta" > "$RUNDIR/samples.csv.tmp"
cat "$RUNDIR/samples.csv" >> "$RUNDIR/samples.csv.tmp"
mv "$RUNDIR/samples.csv.tmp" "$RUNDIR/samples.csv"

info
"$EVAL_BIN" run "$RUNDIR/samples.csv" || true
info
info "Fertig. Auswertung aller Laeufe:  $EVAL_BIN verdict <runs-wurzel>"
