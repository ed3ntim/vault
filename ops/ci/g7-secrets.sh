#!/bin/sh
# Gate G-7 — Secret-Scanning + Log-Leak-Regel
# (spec/engineering-setup.md §3.1, §4; CLAUDE.md).
#
#   "Keine Schluessel, IDs, Onion-Adressen oder Klartexte in Logs —
#    CI-Regel gegen println!/log:: in Krypto-Crates."
#
# Teil A: Secrets im Repository.
# Teil B: Ausgabe-Makros in sicherheitsrelevanten Crates. Die Regel ist
#         bewusst haerter als "keine Geheimnisse loggen": es wird gar nicht
#         geloggt. Was nicht ausgegeben wird, kann nicht leaken.
set -eu

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
fail=0

violation() { printf 'G-7 VERSTOSS: %s\n' "$1" >&2; fail=1; }

# Dateien, die geprueft werden: alles ausser VCS-, Build- und Lock-Artefakten.
scan_files() {
    find "$REPO" -type f \
        -not -path '*/.git/*' \
        -not -path '*/target/*' \
        -not -path '*/ops/ci/*' \
        -not -path '*/corpus/*' \
        -not -path '*/artifacts/*' \
        | sort
}

# --- Teil A: Secrets -------------------------------------------------------
# Muster mit sehr geringer Fehlalarmquote.
SECRET_PATTERNS='-----BEGIN [A-Z ]*PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{36}\b|\bxox[baprs]-[0-9A-Za-z-]{10,}'
# Onion-v3-Adresse: 56 Zeichen Base32 + .onion (gesamtkonzept.md §2.1).
ONION_PATTERN='\b[a-z2-7]{56}\.onion\b'

for f in $(scan_files); do
    case "$f" in *.lock|*Cargo.lock) continue ;; esac
    # -e ist zwingend: das erste Muster beginnt mit '-' und wuerde sonst als
    # Option gelesen. Ohne -e blieb das Gate bei echten Key-Headern gruen.
    hits="$(grep -nEI -e "$SECRET_PATTERNS" "$f" 2>/dev/null || true)"
    [ -n "$hits" ] && { violation "moegliches Secret in ${f#"$REPO/"}:"; printf '%s\n' "$hits" >&2; }
    hits="$(grep -nEI -e "$ONION_PATTERN" "$f" 2>/dev/null || true)"
    [ -n "$hits" ] && { violation "Onion-Adresse in ${f#"$REPO/"}:"; printf '%s\n' "$hits" >&2; }
done
echo "G-7: Secret-Scan abgeschlossen"

# --- Teil B: Log-Leak-Regel ------------------------------------------------
# Gilt fuer alle sicherheitsrelevanten Crates, nicht nur fuer die Krypto.
LOG_CRATES="vault-crypto vault-identity vault-wire vault-transport vault-delivery vault-groups vault-storage"
LOG_PATTERNS='\bprintln!|\beprintln!|\bprint!|\beprint!|\bdbg!|\blog::|\btracing::|std::io::stdout|std::io::stderr'

for c in $LOG_CRATES; do
    dir="$REPO/core/$c/src"
    [ -d "$dir" ] || continue
    hits="$(grep -rnE "$LOG_PATTERNS" "$dir" 2>/dev/null \
            | grep -vE ':[0-9]+: *(//|//!|///)' || true)"
    if [ -n "$hits" ]; then
        violation "Ausgabe-Makro in $c (Log-Leak-Regel §3.1):"
        printf '%s\n' "$hits" >&2
    fi
done
echo "G-7: Log-Leak-Regel geprueft"

if [ "$fail" -eq 0 ]; then
    echo "G-7 OK — keine Secrets, keine Ausgabe aus sicherheitsrelevanten Crates"
else
    echo "G-7 FEHLGESCHLAGEN" >&2
fi
exit "$fail"
