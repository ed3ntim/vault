#!/bin/sh
# Gate G-2 — Tests gruen inkl. Krypto-Vektoren und FSM-Modelltests
# (spec/engineering-setup.md §4).
#
# Enthaelt zusaetzlich die Durchsetzung der Coding-Regeln aus §3.1:
# `cargo clippy -D warnings` traegt die Workspace-Lints aus core/Cargo.toml
# (kein unwrap()/expect(), keine Ausgabe-Makros, kein todo!/unimplemented!,
# keine panic-faehige Indizierung in Parsern).
set -eu

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO/core"

echo "G-2: cargo fmt --check"
cargo fmt --all -- --check

echo "G-2: cargo clippy (-D warnings)"
cargo clippy --workspace --all-targets --all-features -- -D warnings

echo "G-2: cargo test"
cargo test --workspace --all-features

echo "G-2 OK"
