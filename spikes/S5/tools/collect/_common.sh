#!/bin/sh
# Gemeinsame Hilfsfunktionen der S5-Messskripte.
# Wird von den anderen Skripten mit `. "$(dirname "$0")/_common.sh"` geladen.
#
# Grundsaetze (CLAUDE.md):
#  - Kein Netzverkehr ausser adb zum Messgeraet. Kein Upload, keine Telemetrie.
#  - Keine Schluessel, Onion-Adressen oder Kontakt-IDs in Ausgaben.
#    Die Skripte lesen ausschliesslich Systemzaehler, niemals App-Daten.
#  - Geraetebezeichner ist ein frei gewaehltes Label (DEV-A), nicht die Seriennummer.

set -eu

: "${ADB:=adb}"
: "${S5_SERIAL:=}"
: "${S5_DEVICE_LABEL:=DEV-A}"

adb_() {
  if [ -n "$S5_SERIAL" ]; then
    "$ADB" -s "$S5_SERIAL" "$@"
  else
    "$ADB" "$@"
  fi
}

sh_() { adb_ shell "$@"; }

die() { echo "FEHLER: $*" >&2; exit 1; }
warn() { echo "WARNUNG: $*" >&2; }
info() { echo "$*"; }

need_device() {
  command -v "$ADB" >/dev/null 2>&1 || die "adb nicht im PATH"
  state=$(adb_ get-state 2>/dev/null || true)
  [ "$state" = "device" ] || die "kein Geraet erreichbar (adb get-state='$state')"
}

# --- Rohwerte aus dumpsys ---------------------------------------------------

# $1 = Feldname in `dumpsys battery`
battery_field() {
  sh_ dumpsys battery 2>/dev/null | tr -d '\r' | awk -F': *' -v k="$1" '
    { key=$1; gsub(/^[ \t]+/,"",key); if (key==k) { print $2; exit } }'
}

battery_level()   { battery_field "level"; }
battery_temp_dc() { battery_field "temperature"; }   # Zehntelgrad Celsius
battery_volt_mv() { battery_field "voltage"; }       # Millivolt
battery_counter() { battery_field "Charge counter"; } # Mikroamperestunden

# 1 = am Ladegeraet, 0 = nicht
battery_plugged() {
  ac=$(battery_field "AC powered" || echo false)
  usb=$(battery_field "USB powered" || echo false)
  wl=$(battery_field "Wireless powered" || echo false)
  case "$ac$usb$wl" in
    *true*) echo 1 ;;
    *)      echo 0 ;;
  esac
}

# 1 = Display an
screen_on() {
  v=$(sh_ dumpsys deviceidle get screen 2>/dev/null | tr -d '\r ' || true)
  case "$v" in
    true)  echo 1; return ;;
    false) echo 0; return ;;
  esac
  v=$(sh_ dumpsys power 2>/dev/null | tr -d '\r' | awk -F= '/mWakefulness=/{print $2; exit}')
  case "$v" in
    Awake) echo 1 ;;
    "")    echo "-" ;;
    *)     echo 0 ;;
  esac
}

thermal_status() {
  sh_ dumpsys thermalservice 2>/dev/null | tr -d '\r' \
    | awk -F': *' '/^ *Thermal Status:/{print $2; exit}'
}

doze_state() {
  sh_ dumpsys deviceidle get deep 2>/dev/null | tr -d '\r ' || true
}

uptime_s() {
  sh_ cat /proc/uptime 2>/dev/null | tr -d '\r' | awk '{printf "%d", $1}'
}

now_unix() { date +%s; }

csv_header() {
  echo "t_unix,level_pct,charge_uah,voltage_uv,temp_dc,thermal_status,screen_on,plugged"
}

# Eine Messzeile im Sample-CSV-Format ausgeben.
sample_row() {
  t=$(now_unix)
  lvl=$(battery_level  || echo "")
  cc=$(battery_counter || echo "")
  mv=$(battery_volt_mv || echo "")
  tc=$(battery_temp_dc || echo "")
  th=$(thermal_status  || echo "")
  sc=$(screen_on       || echo "-")
  pl=$(battery_plugged || echo "-")
  [ -n "$lvl" ] || return 1
  [ -n "$cc" ] || cc="-"
  if [ -n "$mv" ]; then uv=$((mv * 1000)); else uv="-"; fi
  [ -n "$tc" ] || tc="-"
  [ -n "$th" ] || th="-"
  echo "$t,$lvl,$cc,$uv,$tc,$th,$sc,$pl"
}
