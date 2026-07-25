#!/bin/sh
# Gate G-4 — cargo-vet: alle Dependencies geprueft oder freigegeben
# (spec/engineering-setup.md §4; gesamtkonzept.md §2.11, SC-5).
#
# Jede Exemption ist eine bewusst offene Stelle in der Lieferkette und muss
# im jeweiligen supply-chain/config.toml stehen. Das Gate laeuft mit
# --locked: eine Aenderung am Dependency-Graph ohne Audit bricht den Build.
set -eu

REPO="$(cd "$(dirname "$0")/../.." && pwd)"

command -v cargo-vet >/dev/null 2>&1 || {
    echo "G-4 FEHLGESCHLAGEN: cargo-vet nicht installiert (cargo install --locked cargo-vet)" >&2
    exit 1
}

echo "G-4: core/"
cargo vet --manifest-path "$REPO/core/Cargo.toml" --locked

echo "G-4: tests/fuzz/"
cargo vet --manifest-path "$REPO/tests/fuzz/Cargo.toml" --locked

echo "G-4 OK"
