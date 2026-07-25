#!/bin/sh
# OPTIONALER Mitschnitt waehrend eines Laufs (Fuellstand, Temperatur,
# Thermal-Status) ueber WLAN-adb.
#
# WICHTIG — Messartefakt:
# Jede adb-Abfrage weckt das Geraet und verhindert tiefe Doze-Phasen. Dieser
# Mitschnitt verfaelscht die Messung dadurch nach oben. Er ist deshalb
#   * NICHT der Standardweg fuer die Gate-Laeufe (dort: History-Rekonstruktion
#     ohne Polling, s5-end-run.sh), und
#   * nur zulaessig, wenn sein Eigenverbrauch mit dem Kontrolllauf K3
#     (MESSPROTOKOLL.md §7) beziffert wurde und alle verglichenen Reihen
#     denselben Mitschnitt verwenden.
#
# Sinnvoll ist er fuer: Thermal-Verlauf (steht in der History nicht),
# Screening-Laeufe und Fehlersuche.
#
# Aufruf:  S5_SERIAL=... sh s5-sample.sh <laufverzeichnis> [intervall_s]
# Abbruch mit Ctrl-C; die Dateien bleiben verwertbar.

. "$(dirname "$0")/_common.sh"

RUNDIR="${1:-}"
INTERVAL="${2:-300}"
[ -n "$RUNDIR" ] || die "Aufruf: s5-sample.sh <laufverzeichnis> [intervall_s]"
[ -d "$RUNDIR" ] || die "$RUNDIR ist kein Verzeichnis"
case "$INTERVAL" in ''|*[!0-9]*) die "Intervall muss eine Zahl in Sekunden sein" ;; esac
[ "$INTERVAL" -ge 60 ] || die "Intervall < 60 s verfaelscht die Messung zu stark"

need_device

CSV="$RUNDIR/polled-samples.csv"
THERM="$RUNDIR/polled-thermalservice.txt"

if [ ! -f "$CSV" ]; then
  {
    echo "# s5-sample v1"
    echo "# source=polling (Messartefakt, siehe Kopf von s5-sample.sh)"
    echo "# poll_interval_s=$INTERVAL"
    awk '/^# /{print}' "$RUNDIR/run.meta" 2>/dev/null || true
    csv_header
  } > "$CSV"
fi

info "Mitschnitt laeuft: alle ${INTERVAL}s -> $CSV  (Ctrl-C beendet)"
while true; do
  row=$(sample_row || true)
  if [ -n "$row" ]; then
    echo "$row" >> "$CSV"
  else
    warn "Messzeile konnte nicht gelesen werden (Geraet weg?)"
  fi
  {
    echo "### sample t_unix=$(now_unix)"
    sh_ dumpsys thermalservice 2>/dev/null | tr -d '\r' || true
  } >> "$THERM"
  sleep "$INTERVAL"
done
