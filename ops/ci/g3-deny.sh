#!/bin/sh
# Gate G-3 — cargo-deny: Lizenzen, Advisories, Duplikate
# (spec/engineering-setup.md §4; SC-5 „gepinnte Dependencies").
#
# Eine Policy-Datei (core/deny.toml) fuer beide Manifeste: den Kern und das
# Fuzz-Werkzeug. Fehlt das Werkzeug, bricht das Gate ab — es wird nicht
# stillschweigend uebersprungen (CLAUDE.md: CI-Gates nicht umgehen).
set -eu

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
CONFIG="$REPO/core/deny.toml"

command -v cargo-deny >/dev/null 2>&1 || {
    echo "G-3 FEHLGESCHLAGEN: cargo-deny nicht installiert (cargo install --locked cargo-deny)" >&2
    exit 1
}

echo "G-3: core/"
cargo deny --manifest-path "$REPO/core/Cargo.toml" --config "$CONFIG" check

echo "G-3: tests/fuzz/"
cargo deny --manifest-path "$REPO/tests/fuzz/Cargo.toml" --config "$CONFIG" check

echo "G-3 OK"
