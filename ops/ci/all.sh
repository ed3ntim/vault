#!/bin/sh
# Faehrt die lokal ausfuehrbaren Gates G-2 … G-8 nacheinander und gibt am
# Ende eine Uebersicht aus. Exit-Code 1, sobald ein Gate rot ist.
#
# G-1 (Build auf allen Zielplattformen) laeuft in CI als Matrix; lokal deckt
# G-2 den Build der jeweiligen Plattform mit ab.
# G-9/G-10 (reproduzierbarer Build, m-of-n-Signatur) sind Release-Gates und
# nicht Teil dieses Laufs.
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
GATES="g2-tests g3-deny g4-vet g5-layers g6-unsafe g7-secrets g8-fuzz-smoke"
results=""
overall=0

for g in $GATES; do
    printf '\n=========== %s ===========\n' "$g"
    if sh "$DIR/$g.sh"; then
        results="$results
  $g: OK"
    else
        results="$results
  $g: FEHLGESCHLAGEN"
        overall=1
    fi
done

printf '\n=========== Uebersicht ===========%s\n' "$results"
exit "$overall"
