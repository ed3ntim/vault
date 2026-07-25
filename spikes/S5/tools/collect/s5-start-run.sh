#!/bin/sh
# Startet einen S5-Messlauf: Vorpruefung, Statistik zuruecksetzen, Metadaten
# festhalten. Danach wird das Geraet 24 h in Ruhe gelassen.
#
# Aufruf:
#   S5_SERIAL=192.168.x.y:5555 S5_DEVICE_LABEL=DEV-A \
#   sh s5-start-run.sh <messreihe> <lauf-id> <ausgabeverzeichnis>
#
# Beispiel:
#   sh s5-start-run.sh R3 01 ../../runs
#   -> legt ../../runs/R3/DEV-A-R3-01/ an
#
# Die Messreihen sind in MESSPROTOKOLL.md §3 definiert:
#   R0 Baseline · R1 Onion · R2 +Snowflake · R3 +Shaping · R4 +BLE
#   R5 Referenz-Messenger · K1/K2 Kontrollen

. "$(dirname "$0")/_common.sh"

SERIES="${1:-}"
RUNID="${2:-}"
OUTROOT="${3:-}"
[ -n "$SERIES" ] && [ -n "$RUNID" ] && [ -n "$OUTROOT" ] || \
  die "Aufruf: s5-start-run.sh <messreihe> <lauf-id> <ausgabeverzeichnis>"

case "$SERIES" in
  R0|R1|R2|R3|R4|R5|K1|K2) ;;
  *) die "unbekannte Messreihe '$SERIES' (erlaubt: R0 R1 R2 R3 R4 R5 K1 K2)" ;;
esac

need_device
sh "$(dirname "$0")/s5-precheck.sh" || die "Vorpruefung gerissen — Lauf nicht gestartet"

RUNDIR="$OUTROOT/$SERIES/$S5_DEVICE_LABEL-$SERIES-$RUNID"
[ -e "$RUNDIR" ] && die "$RUNDIR existiert bereits — Lauf-ID neu vergeben"
mkdir -p "$RUNDIR"

START=$(now_unix)

# Statistik zuruecksetzen: ab hier zaehlt der Lauf.
sh_ dumpsys batterystats --reset >/dev/null 2>&1 || warn "batterystats --reset nicht bestaetigt"
sh_ dumpsys batterystats --enable full-history >/dev/null 2>&1 || \
  warn "full-history nicht aktivierbar (aeltere Android-Version?)"

{
  echo "# s5-run v1"
  echo "# series=$SERIES"
  echo "# run_id=$RUNID"
  echo "# device=$S5_DEVICE_LABEL"
  echo "# start_unix=$START"
  echo "# start_iso=$(date -u -d "@$START" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "# start_level=$(battery_level)"
  echo "# start_charge_uah=$(battery_counter)"
  echo "# start_temp_dc=$(battery_temp_dc)"
  echo "# start_thermal=$(thermal_status)"
  echo "# doze=$(doze_state)"
  echo "# android_release=$(sh_ getprop ro.build.version.release | tr -d '\r')"
  echo "# android_sdk=$(sh_ getprop ro.build.version.sdk | tr -d '\r')"
  echo "# build_id=$(sh_ getprop ro.build.id | tr -d '\r')"
  echo "# model=$(sh_ getprop ro.product.model | tr -d '\r')"
  echo "# airplane_mode=$(sh_ settings get global airplane_mode_on | tr -d '\r ')"
  echo "# wifi_on=$(sh_ settings get global wifi_on | tr -d '\r ')"
  echo "# bluetooth_on=$(sh_ settings get global bluetooth_on | tr -d '\r ')"
  echo "# location_mode=$(sh_ settings get secure location_mode | tr -d '\r ')"
  # Von Hand nachzutragen (MESSPROTOKOLL.md §4):
  echo "# design_capacity_uah=TODO"
  echo "# ambient_temp_c=TODO"
  echo "# wifi_rssi_dbm=TODO"
  echo "# app_build=TODO"
  echo "# operator_note=TODO"
} > "$RUNDIR/run.meta"

info "Lauf gestartet: $SERIES/$RUNID  Geraet=$S5_DEVICE_LABEL"
info "Verzeichnis   : $RUNDIR"
info "Startzeit     : $START"
info
info "Jetzt: Geraet unberuehrt liegen lassen, Display aus, nicht laden."
info "Nach >= 24 h:  sh s5-end-run.sh $RUNDIR"
info
info "TODO-Felder in $RUNDIR/run.meta von Hand ausfuellen"
info "(design_capacity_uah, ambient_temp_c, wifi_rssi_dbm, app_build)."
