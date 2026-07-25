#!/bin/sh
# Erzeugt SYNTHETISCHE Beispieldaten fuer die Werkzeugtests von s5-eval.
#
# ACHTUNG — ausdruecklich KEINE Messwerte:
# Die Entladeraten unten sind frei gewaehlte Rechenkonstanten, mit denen die
# Auswertelogik geprueft wird (ein Kriterium bestanden, eines gerissen, ein
# Lauf verworfen). Sie sind KEINE Erwartungswerte fuer Vault und duerfen
# nirgends als solche zitiert werden. Erst die Messung auf echten
# Referenzgeraeten liefert Zahlen (siehe ../../MESSPROTOKOLL.md).
#
# Aufruf:  sh gen-synthetic.sh [zielverzeichnis]
set -eu

OUT="${1:-$(dirname "$0")/synthetic-runs}"
START_UNIX=1750000000
START_LEVEL=95
DESIGN_UAH=4000000
STEP_MIN=15
HOURS=24

# Reihe:Rate1,Rate2,Rate3  (Prozentpunkte pro 24 h, frei gewaehlt)
SERIES_SPEC="R0:4.0,4.2,3.8
R1:8.0,8.4,7.6
R2:9.5,9.9,9.1
R3:11.0,11.4,10.6
R4:15.0,15.4,14.6
R5:6.0,6.4,5.6"

gen_run() {
  series="$1"; idx="$2"; rate="$3"; screen="$4"; file="$5"
  {
    echo "# s5-sample v1"
    echo "# synthetic=true"
    echo "# generator=gen-synthetic.sh"
    echo "# series=$series"
    echo "# device=SYN-A"
    echo "# design_capacity_uah=$DESIGN_UAH"
    echo "# note=SYNTHETISCH, keine Messung. Rate=${rate} %/24h frei gewaehlt."
    echo "t_unix,level_pct,charge_uah,voltage_uv,temp_dc,thermal_status,screen_on,plugged"
  } > "$file"
  awk -v start="$START_UNIX" -v lvl="$START_LEVEL" -v rate="$rate" \
      -v cap="$DESIGN_UAH" -v step="$STEP_MIN" -v hours="$HOURS" \
      -v screen="$screen" -v idx="$idx" '
    BEGIN {
      n = hours * 60 / step
      for (i = 0; i <= n; i++) {
        h = i * step / 60.0
        exact = lvl - rate * h / 24.0
        charge = cap * exact / 100.0
        # ganzzahliger Fuellstand wie vom System gemeldet
        printf "%d,%d,%.0f,%d,%d,0,%d,0\n", start + idx*100000 + h*3600, int(exact), charge, 4180000 - h*4000, 300, screen
      }
    }' >> "$file"
}

echo "$SERIES_SPEC" | while IFS=: read -r series rates; do
  [ -n "$series" ] || continue
  mkdir -p "$OUT/$series"
  i=1
  echo "$rates" | tr ',' '\n' | while read -r rate; do
    [ -n "$rate" ] || continue
    gen_run "$series" "$i" "$rate" 0 "$OUT/$series/synthetic-$series-0$i.csv"
    i=$((i + 1))
  done
done

# Ein absichtlich ungueltiger Lauf: Display war an -> muss verworfen werden.
mkdir -p "$OUT/R1"
gen_run "R1" 4 8.2 1 "$OUT/R1/synthetic-R1-04-ungueltig.csv"

echo "synthetische Testdaten geschrieben nach: $OUT"
