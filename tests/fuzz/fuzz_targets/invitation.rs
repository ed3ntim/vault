//! Fuzz-Target `invitation` (Gate G-8, spec/engineering-setup.md §3.2).
//!
//! Zieltyp: `Invitation` — Kontaktaufbau out-of-band, spec/protokoll-spec.md §4.
//!
//! Geprueft werden drei Invarianten auf Angreifer-kontrollierten Bytes:
//! 1. kein Panic, keine Endlosschleife, keine Allokation proportional zu
//!    einer Laengenangabe — nur `Err`;
//! 2. die Parserbasis (kanonisches CBOR, laengenpraefigierte Felder) bleibt
//!    robust;
//! 3. **Kanonizitaet**: was sich dekodieren laesst, muss sich bitidentisch
//!    zurueck kodieren lassen. Zwei verschiedene Bytefolgen duerfen nie
//!    dieselbe Invitation ergeben — sonst waere die Signatur ueber die
//!    Struktur (§4 `sig`) nicht eindeutig.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vault_wire::cbor;
use vault_wire::invitation::Invitation;
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

    if let Ok(inv) = Invitation::decode(data) {
        let wieder = inv.encode().expect("dekodierte Invitation muss kodierbar sein");
        assert_eq!(
            wieder.as_slice(),
            data,
            "Dekodieren und Kodieren muss bitidentisch sein"
        );
    }
});
