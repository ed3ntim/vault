#!/bin/sh
# Gate G-5 — Schichtregel (spec/engineering-setup.md §2, §4).
#
#   "vault-crypto hat KEINE I/O- und keine Netzabhaengigkeiten.
#    vault-transport kennt KEINE Klartext-Payloads.
#    Verstoesse brechen den Build."
#
# Geprueft wird strukturell, nicht lexikalisch:
#   1. vault-crypto darf ueberhaupt keine Abhaengigkeit haben (auch keine
#      transitive), die I/O oder Netz mitbringt — geprueft ueber den
#      vollstaendigen Dependency-Baum gegen eine Allowlist.
#   2. vault-crypto darf im Quelltext keine I/O-, Netz- oder Prozess-APIs
#      der Standardbibliothek verwenden.
#   3. vault-transport darf von keinem Crate abhaengen, das Klartext-Payloads
#      kennt. Ein lexikalischer Test auf Woerter wie "Klartext" wuerde nur
#      Fehlalarme in Doku-Kommentaren erzeugen; die Dependency-Richtung ist
#      die pruefbare Eigenschaft.
set -eu

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
CORE="$REPO/core"
fail=0

note() { printf 'G-5: %s\n' "$1"; }
violation() { printf 'G-5 VERSTOSS: %s\n' "$1" >&2; fail=1; }

# --- 1. vault-crypto: Dependency-Baum -------------------------------------
# Allowlist: erlaubte Pakete im Baum von vault-crypto. Erweiterung nur mit
# ADR-Bezug (ADR-05 legt die zulaessigen Verfahren fest).
CRYPTO_ALLOWED="vault-crypto zeroize zeroize_derive subtle"

tree="$(cd "$CORE" && cargo tree --quiet -p vault-crypto -e normal --prefix none 2>/dev/null \
        | awk 'NF {print $1}' | sort -u)"
for pkg in $tree; do
    case " $CRYPTO_ALLOWED " in
        *" $pkg "*) ;;
        *) violation "vault-crypto haengt an '$pkg' — nicht in der Allowlist (Schichtregel §2)" ;;
    esac
done
note "Dependency-Baum vault-crypto geprueft"

# --- 2. vault-crypto: keine I/O-, Netz- oder Prozess-APIs im Quelltext -----
FORBIDDEN_IN_CRYPTO='std::net|std::fs|std::io|std::process|std::os|std::env|tokio|async_std|mio::|socket2|reqwest'
hits="$(grep -rnE "$FORBIDDEN_IN_CRYPTO" "$CORE/vault-crypto/src" 2>/dev/null \
        | grep -vE '^[^:]+:[0-9]+: *(//|//!|///)' || true)"
if [ -n "$hits" ]; then
    violation "I/O-/Netz-API in vault-crypto:"
    printf '%s\n' "$hits" >&2
fi
note "Quelltext vault-crypto geprueft"

# --- 3. vault-transport: keine Payload-Crates -----------------------------
PAYLOAD_CRATES="vault-wire vault-crypto vault-identity vault-delivery vault-groups vault-storage vault-core"
deps="$(awk '/^\[dependencies\]/{f=1;next} /^\[/{f=0} f && /=/{sub(/ *=.*/,""); print}' \
        "$CORE/vault-transport/Cargo.toml" 2>/dev/null || true)"
for d in $deps; do
    for p in $PAYLOAD_CRATES; do
        [ "$d" = "$p" ] && violation "vault-transport haengt an '$d' — kennt damit Klartext-Payloads (§2)"
    done
done
note "Dependency-Richtung vault-transport geprueft"

# --- 4. Zyklen-/Richtungspruefung der uebrigen Crates ----------------------
# vault-ffi ist die oberste Schicht: nur vault-core darf darunter liegen.
ffi_deps="$(awk '/^\[dependencies\]/{f=1;next} /^\[/{f=0} f && /=/{sub(/ *=.*/,""); print}' \
        "$CORE/vault-ffi/Cargo.toml" 2>/dev/null || true)"
for d in $ffi_deps; do
    [ "$d" = "vault-core" ] || violation "vault-ffi haengt an '$d' — erlaubt ist nur vault-core"
done
note "Dependency-Richtung vault-ffi geprueft"

if [ "$fail" -eq 0 ]; then
    echo "G-5 OK — Schichtregel eingehalten"
else
    echo "G-5 FEHLGESCHLAGEN" >&2
fi
exit "$fail"
