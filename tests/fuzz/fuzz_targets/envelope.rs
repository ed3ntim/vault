//! Fuzz-Target `envelope` (Gate G-8, spec/engineering-setup.md §3.2).
//!
//! Zieltyp: `Envelope` — Aussenhuelle einer zugestellten Nachricht, spec/protokoll-spec.md §8, §9.
//!
//! Deckung heute: die gemeinsame Parserbasis von `vault-wire`
//! (deterministisches CBOR nach RFC 8949 §4.2 und laengenpraefigierte
//! Felder). Der typspezifische Decoder folgt mit Sprint 0 #3 und wird hier
//! eingehaengt. Siehe tests/fuzz/README.md.
//!
//! Invariante: kein Panic, keine Endlosschleife, keine Allokation
//! proportional zu einer Angreifer-Laengenangabe — nur `Err`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vault_wire::cbor;
use vault_wire::lenprefix::FieldReader;

/// Obergrenze fuer ein einzelnes laengenpraefigiertes Feld beim Fuzzing.
const MAX_FIELD_LEN: usize = 1 << 16;

fuzz_target!(|data: &[u8]| {
    let _ = cbor::validate_canonical(data);

    let mut reader = FieldReader::new(data, MAX_FIELD_LEN);
    loop {
        match reader.next_field() {
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
        }
    }
});
