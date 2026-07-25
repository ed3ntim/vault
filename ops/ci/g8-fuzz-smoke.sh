#!/bin/sh
# Gate G-8 — Fuzzing-Smoke (spec/engineering-setup.md §3.2, §4).
#
#   "Dauerhafte Fuzz-Targets: Invitation, Envelope, GroupFrame, Attestation"
#   "Fuzzing-Smoke (kurze Laeufe; lange Laeufe nightly)"
#
# Laufzeit je Target ueber FUZZ_SECONDS steuerbar (Default 30 s).
# Die aktuelle Deckung der Targets ist in tests/fuzz/README.md ehrlich
# benannt: heute die gemeinsame Parserbasis von vault-wire, die
# typspezifischen Decoder folgen mit Sprint 0 #3.
set -eu

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
SECONDS_PER_TARGET="${FUZZ_SECONDS:-30}"
TARGETS="invitation envelope group_frame attestation"

command -v cargo-fuzz >/dev/null 2>&1 || {
    echo "G-8 FEHLGESCHLAGEN: cargo-fuzz nicht installiert (cargo install --locked cargo-fuzz)" >&2
    exit 1
}

# Windows: cargo-fuzz baut mit AddressSanitizer, dessen Laufzeit-DLL liegt
# im MSVC-Toolset und nicht im PATH. Ohne sie startet das Target mit
# STATUS_DLL_NOT_FOUND. ASan wird NICHT abgeschaltet, sondern die Laufzeit
# gesucht — ein Fuzzing-Lauf ohne Sanitizer waere ein schwaecheres Gate.
case "$(uname -s 2>/dev/null || echo unknown)" in
    MINGW*|MSYS*|CYGWIN*)
        if [ -z "${ASAN_RUNTIME_DIR:-}" ]; then
            for root in "/c/Program Files/Microsoft Visual Studio" \
                        "/c/Program Files (x86)/Microsoft Visual Studio"; do
                [ -d "$root" ] || continue
                dll="$(find "$root" -type f -path '*Hostx64*' \
                        -name 'clang_rt.asan_dynamic-x86_64.dll' 2>/dev/null | head -1)"
                if [ -n "$dll" ]; then
                    ASAN_RUNTIME_DIR="$(dirname "$dll")"
                    break
                fi
            done
        fi
        if [ -z "${ASAN_RUNTIME_DIR:-}" ]; then
            echo "G-8 FEHLGESCHLAGEN: ASan-Laufzeit (clang_rt.asan_dynamic-x86_64.dll)" >&2
            echo "  nicht gefunden. MSVC-Build-Tools installieren oder ASAN_RUNTIME_DIR setzen." >&2
            exit 1
        fi
        PATH="$ASAN_RUNTIME_DIR:$PATH"
        export PATH
        echo "G-8: ASan-Laufzeit aus $ASAN_RUNTIME_DIR"
        ;;
esac

cd "$REPO"
for t in $TARGETS; do
    echo "G-8: fuzz $t (${SECONDS_PER_TARGET}s)"
    cargo +nightly fuzz run --fuzz-dir tests/fuzz "$t" -- \
        -max_total_time="$SECONDS_PER_TARGET" -max_len=4096
done

echo "G-8 OK"
