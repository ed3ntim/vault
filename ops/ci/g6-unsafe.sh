#!/bin/sh
# Gate G-6 — kein `unsafe` ausserhalb der Whitelist
# (spec/engineering-setup.md §3.1, §4; CLAUDE.md).
#
#   "#![forbid(unsafe_code)] in allen Crates ausser vault-ffi und
#    Transport-Bindings; dort unsafe nur mit dokumentiertem Review durch
#    zwei Personen."
#
# Zwei Pruefungen:
#   1. `unsafe` kommt nur in den Whitelist-Pfaden vor.
#   2. Jede lib.rs ausserhalb von vault-ffi fuehrt tatsaechlich
#      `#![forbid(unsafe_code)]` — sonst waere Pruefung 1 wirkungslos,
#      sobald jemand eine Datei hinzufuegt.
set -eu

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
CORE="$REPO/core"
fail=0

violation() { printf 'G-6 VERSTOSS: %s\n' "$1" >&2; fail=1; }

# Whitelist: FFI-Grenze und Transport-Bindings (§3.1).
is_whitelisted() {
    case "$1" in
        */vault-ffi/*) return 0 ;;
        */vault-transport/src/tor/*) return 0 ;;
        */vault-transport/src/mesh/*) return 0 ;;
        *) return 1 ;;
    esac
}

# --- 1. unsafe ausserhalb der Whitelist -----------------------------------
for f in $(find "$CORE" -name '*.rs' -not -path '*/target/*' | sort); do
    is_whitelisted "$f" && continue
    # Kommentarzeilen und die Attribute forbid/deny(unsafe_code) ausblenden,
    # danach auf das Schluesselwort pruefen.
    hits="$(grep -nE '\bunsafe\b' "$f" \
            | grep -vE ':[0-9]+: *(//|//!|///)' \
            | grep -v 'unsafe_code' || true)"
    if [ -n "$hits" ]; then
        violation "unsafe ausserhalb der Whitelist in ${f#"$REPO/"}:"
        printf '%s\n' "$hits" >&2
    fi
done

# --- 2. forbid(unsafe_code) ist tatsaechlich gesetzt ----------------------
for f in $(find "$CORE" -name 'lib.rs' -not -path '*/target/*' | sort); do
    case "$f" in */vault-ffi/*) continue ;; esac
    grep -q '#!\[forbid(unsafe_code)\]' "$f" \
        || violation "${f#"$REPO/"} fuehrt kein #![forbid(unsafe_code)] (§3.1)"
done

if [ "$fail" -eq 0 ]; then
    echo "G-6 OK — kein unsafe ausserhalb der Whitelist, forbid(unsafe_code) ueberall gesetzt"
else
    echo "G-6 FEHLGESCHLAGEN" >&2
fi
exit "$fail"
