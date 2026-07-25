#!/usr/bin/env bash
# Spike S3 — liest die fuer die Revocation-Latenz massgeblichen Konstanten und
# Codestellen direkt aus dem Quelltext der installierten Crate-Version.
# Nicht aus Dokumentation. Reproduzierbar.
#
# Aufruf: bash spikes/S3/pruefe-arti-konstanten.sh
set -u

SRC="$HOME/.cargo/registry/src"
HS=$(find "$SRC" -maxdepth 2 -type d -name "tor-hsservice-0.44.0" | head -1)
OUT="$(dirname "$0")/ergebnisse/T-arti-konstanten.txt"
mkdir -p "$(dirname "$OUT")"

if [ -z "$HS" ]; then
  echo "tor-hsservice-0.44.0 nicht im Registry-Cache gefunden." >&2
  exit 1
fi

{
  echo "# Spike S3 — zeitbestimmende Konstanten in tor-hsservice 0.44.0"
  echo "# $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# Quelle: $HS"
  echo
  echo "== 1. Lebensdauer des publizierten Descriptors =="
  grep -n "IPT_PUBLISH_UNCERTAIN\|IPT_PUBLISH_CERTAIN" "$HS/src/ipt_mgr.rs" | head -6
  echo
  echo "== 2. Wie lange ein alter Intro-Point nach Ablauf noch gehalten wird =="
  grep -n -A 3 "^const IPT_PUBLISH_EXPIRY_SLOP" "$HS/src/ipt_set.rs"
  echo
  echo "== 3. Zeitbudget fuer den Descriptor-Upload =="
  grep -n "OVERALL_UPLOAD_TIMEOUT\|UPLOAD_RATE_LIM_THRESHOLD" "$HS/src/publish/reactor.rs" | head -6
  echo
  echo "== 4. Ab wann ein Intro-Point als fehlerhaft gilt =="
  grep -n "FAULTY_IPT_THRESHOLD" "$HS/src/ipt_establish.rs" | head -3
  echo
  echo "== 5. Wann ein Intro-Point ueberhaupt vergessen wird =="
  grep -n -B 2 -A 12 "Forget old IPTs (after the last descriptor mentioning them has expired)" "$HS/src/ipt_mgr.rs"
  echo
  echo "== 6. Rotationszeitpunkt wird zufaellig aus Konsensparametern gezogen =="
  grep -n -B 2 -A 12 "hs_intro_min_lifetime" "$HS/src/ipt_mgr.rs" | head -30
  echo
  echo "== 7. Neustart stellt DIESELBEN Intro-Points wieder her =="
  grep -n "IptExpectExistingKeys\|start_accepting\|fn load_restart" "$HS/src/ipt_mgr/persist.rs"
  echo
  echo "== 8. Entfernen eines Clients entzieht laut Doku keinen Zugriff =="
  sed -n '48,64p' "$HS/src/config/restricted_discovery.rs"
  echo
  echo "== 9. reconfigure erreicht bestehende Verbindungen moeglicherweise nicht =="
  grep -n -A 4 "TODO (#1153, #1209)" "$HS/src/lib.rs"
  echo
  echo "== 10. pause() ist nicht implementiert =="
  grep -n -B 6 -A 3 "TODO (#1231)" "$HS/src/lib.rs"
} > "$OUT" 2>&1

echo "geschrieben: $OUT"
