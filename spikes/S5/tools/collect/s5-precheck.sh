#!/bin/sh
# Prueft vor jedem Lauf, ob das Geraet im definierten Zustand ist
# (MESSPROTOKOLL.md §4 Randbedingungen, §6 Ruecksetzen zwischen Laeufen).
#
# Aufruf:  S5_SERIAL=<adb-serial> sh s5-precheck.sh
# Exit 0 = alle Pflichtpruefungen bestanden, 1 = mindestens eine gerissen.

. "$(dirname "$0")/_common.sh"

FAILED=0
check() { # $1=Beschreibung $2=ok(0/1) $3=Istwert
  if [ "$2" = "1" ]; then
    printf '  [ok]   %-46s %s\n' "$1" "$3"
  else
    printf '  [FEHL] %-46s %s\n' "$1" "$3"
    FAILED=$((FAILED + 1))
  fi
}
soft() { printf '  [info] %-46s %s\n' "$1" "$2"; }

need_device
echo "S5-Vorpruefung  Geraet=$S5_DEVICE_LABEL"

# --- Verbindung: ueber USB darf NICHT gemessen werden (USB laedt) -----------
TCP=0
case "$S5_SERIAL" in *:*) TCP=1 ;; esac
if [ "$TCP" = 1 ]; then howto="$S5_SERIAL"; else howto="USB oder unbekannt"; fi
check "Verbindung ueber WLAN-adb (kein USB-Laden)" "$TCP" "$howto"

plugged=$(battery_plugged)
ok=0; if [ "$plugged" = "0" ]; then ok=1; fi
check "Geraet nicht am Ladegeraet" "$ok" "plugged=$plugged"

level=$(battery_level)
ok=0
if [ -n "$level" ]; then
  if [ "$level" -le 97 ] && [ "$level" -ge 88 ]; then ok=1; fi
fi
check "Startfuellstand in [88,97] %" "$ok" "level=$level %"

scr=$(screen_on)
ok=0; if [ "$scr" = "0" ]; then ok=1; fi
check "Display aus" "$ok" "screen_on=$scr"

temp=$(battery_temp_dc)
ok=0
if [ -n "$temp" ]; then
  if [ "$temp" -le 320 ]; then ok=1; fi
fi
check "Akkutemperatur <= 32.0 C (abgekuehlt)" "$ok" "temp=$temp (Zehntelgrad)"

th=$(thermal_status)
ok=0; if [ "$th" = "0" ]; then ok=1; fi
check "Thermal-Status NONE" "$ok" "status=$th"

up=$(uptime_s)
ok=0
if [ -n "$up" ]; then
  if [ "$up" -ge 1200 ]; then ok=1; fi
fi
check "Mindestens 20 min seit Neustart (Nachlauf abgeklungen)" "$ok" "uptime=${up}s"

# --- Einstellungen, die die Messung verfaelschen ----------------------------
saver=$(sh_ settings get global low_power 2>/dev/null | tr -d '\r ')
ok=0; if [ "$saver" = "0" ] || [ "$saver" = "null" ] || [ -z "$saver" ]; then ok=1; fi
check "Battery Saver aus" "$ok" "low_power=$saver"

airplane=$(sh_ settings get global airplane_mode_on 2>/dev/null | tr -d '\r ')
soft "Flugmodus (Sollwert je Messreihe)" "airplane_mode_on=$airplane"

adaptive=$(sh_ settings get global adaptive_battery_management_enabled 2>/dev/null | tr -d '\r ')
soft "Adaptive Battery" "$adaptive"

autoupd=$(sh_ settings get global auto_time 2>/dev/null | tr -d '\r ')
soft "auto_time" "$autoupd"

soft "Doze-Zustand" "$(doze_state)"
soft "Akkuzaehler (uAh)" "$(battery_counter)"
soft "Android-Version" "$(sh_ getprop ro.build.version.release | tr -d '\r')"
soft "Build" "$(sh_ getprop ro.build.id | tr -d '\r')"

echo
if [ "$FAILED" -eq 0 ]; then
  echo "Vorpruefung bestanden. Lauf kann gestartet werden (s5-start-run.sh)."
  exit 0
fi
echo "$FAILED Pflichtpruefung(en) gerissen. Lauf NICHT starten."
exit 1
