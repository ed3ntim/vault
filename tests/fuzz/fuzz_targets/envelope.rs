//! Fuzz-Target `envelope` (Gate G-8, spec/engineering-setup.md §3.2).
//!
//! Zieltyp: `Envelope` und `Payload` — spec/protokoll-spec.md §8, §9.
//!
//! Invarianten wie im Target `invitation`: kein Panic, robuste Parserbasis,
//! und bitidentischer Rueckweg fuer alles, was sich dekodieren laesst.
//! Letzteres traegt hier zusaetzlich, weil `ad = H(dr_header)` (§8) an die
//! Kodierung gebunden ist.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vault_wire::cbor;
use vault_wire::envelope::{Envelope, Payload};
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

    if let Ok(env) = Envelope::decode(data) {
        let wieder = env.encode().expect("dekodierter Envelope muss kodierbar sein");
        assert_eq!(wieder.as_slice(), data, "Envelope: Rueckweg nicht bitidentisch");
    }

    if let Ok(p) = Payload::decode(data) {
        let wieder = p.encode().expect("dekodierte Payload muss kodierbar sein");
        assert_eq!(wieder.as_slice(), data, "Payload: Rueckweg nicht bitidentisch");
    }
});
