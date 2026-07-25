//! Pruefung auf deterministisch kodiertes CBOR.
//!
//! Normativ: `spec/protokoll-spec.md` §1 — „Wire-Kodierung: **CBOR**
//! (deterministisch, RFC 8949 §4.2). Kein Feld ohne explizite Laenge."
//! Ergaenzend ADR-11 (deterministisches CBOR als Wire-Format,
//! „Serializer-Determinismus muss getestet werden (S7)").
//!
//! [`validate_canonical`] prueft einen Byte-Slice auf beides:
//!
//! 1. **Wohlgeformtheit** — jedes Element ist vollstaendig und syntaktisch
//!    gueltig.
//! 2. **Determinismus** nach RFC 8949 §4.2.1:
//!    * Argumente in der kuerzest moeglichen Form (§4.2.1 Punkt 1),
//!    * keine Elemente unbestimmter Laenge (§4.2.1 Punkt 2),
//!    * Map-Schluessel bytweise aufsteigend sortiert und duplikatfrei
//!      (§4.2.1 Punkt 3).
//!
//! Zusaetzlich schraenkt dieses Profil ein, was `spec/protokoll-spec.md`
//! nicht braucht und was Parserfehler anzieht:
//!
//! * **Keine Tags** (Major Type 6). Die Spec kennt keine.
//! * **Keine Gleitkommazahlen.** §1 legt alle Zahlwerte auf `u64` fest.
//! * **Nur `false`, `true`, `null`** als Simple Values; `undefined` und
//!   unzugewiesene Simple Values werden abgewiesen.
//! * **Tiefenlimit** [`MAX_NESTING_DEPTH`] gegen Stapelerschoepfung durch
//!   Angreifer-kontrollierte Verschachtelung.
//!
//! Hinweis zur Byte-Reihenfolge: CBOR-Koepfe sind nach RFC 8949 in
//! Netzwerk-Byte-Reihenfolge (big-endian) kodiert. Die Festlegung „alle
//! Multi-Byte-Felder little-endian" in §1 betrifft Felder ausserhalb der
//! CBOR-Kodierung (siehe [`crate::lenprefix`]) und steht dazu nicht im
//! Widerspruch.
//!
//! Der Validator bildet **kein** Datenmodell ab. Er nimmt GATE-6
//! („Wire-Format final") nicht vorweg und bleibt auch dann gueltig, wenn die
//! Kodierung spaeter aus einer Bibliothek kommt — als Eingangspruefung auf
//! Angreifer-kontrollierten Bytes.

use crate::error::WireError;

/// Maximale Verschachtelungstiefe von Arrays und Maps.
pub const MAX_NESTING_DEPTH: u32 = 32;

/// Prueft, ob `input` **genau ein** deterministisch kodiertes CBOR-Element
/// enthaelt.
///
/// # Fehler
///
/// Siehe [`WireError`]; jede Abweichung von RFC 8949 §4.2 und vom oben
/// beschriebenen Profil fuehrt zu einem Fehler. Nachlaufende Bytes sind ein
/// Fehler ([`WireError::TrailingBytes`]) — ein Element, nicht ein Strom.
pub fn validate_canonical(input: &[u8]) -> Result<(), WireError> {
    let mut cursor = Cursor { buf: input, pos: 0 };
    validate_item(&mut cursor, 0)?;
    if cursor.pos == input.len() {
        Ok(())
    } else {
        Err(WireError::TrailingBytes)
    }
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take_one(&mut self) -> Result<u8, WireError> {
        let byte = *self.buf.get(self.pos).ok_or(WireError::Truncated)?;
        self.pos = self.pos.checked_add(1).ok_or(WireError::LengthOverflow)?;
        Ok(byte)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::LengthOverflow)?;
        let slice = self.buf.get(self.pos..end).ok_or(WireError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }
}

/// Liest das Argument eines Kopfes und prueft die kuerzest moegliche Form.
fn read_argument(cursor: &mut Cursor<'_>, additional_info: u8) -> Result<u64, WireError> {
    match additional_info {
        0..=23 => Ok(u64::from(additional_info)),
        24 => {
            let raw = cursor.take(1)?;
            let value = u64::from(*raw.first().ok_or(WireError::Truncated)?);
            if value < 24 {
                return Err(WireError::NonMinimalHead);
            }
            Ok(value)
        }
        25 => {
            let raw: [u8; 2] = cursor
                .take(2)?
                .try_into()
                .map_err(|_| WireError::Truncated)?;
            let value = u64::from(u16::from_be_bytes(raw));
            if value <= u64::from(u8::MAX) {
                return Err(WireError::NonMinimalHead);
            }
            Ok(value)
        }
        26 => {
            let raw: [u8; 4] = cursor
                .take(4)?
                .try_into()
                .map_err(|_| WireError::Truncated)?;
            let value = u64::from(u32::from_be_bytes(raw));
            if value <= u64::from(u16::MAX) {
                return Err(WireError::NonMinimalHead);
            }
            Ok(value)
        }
        27 => {
            let raw: [u8; 8] = cursor
                .take(8)?
                .try_into()
                .map_err(|_| WireError::Truncated)?;
            let value = u64::from_be_bytes(raw);
            if value <= u64::from(u32::MAX) {
                return Err(WireError::NonMinimalHead);
            }
            Ok(value)
        }
        28..=30 => Err(WireError::ReservedAdditionalInfo),
        // 31 = unbestimmte Laenge, nach RFC 8949 §4.2.1 unzulaessig
        _ => Err(WireError::IndefiniteLength),
    }
}

fn read_length(cursor: &mut Cursor<'_>, additional_info: u8) -> Result<usize, WireError> {
    let value = read_argument(cursor, additional_info)?;
    usize::try_from(value).map_err(|_| WireError::LengthOverflow)
}

fn validate_item(cursor: &mut Cursor<'_>, depth: u32) -> Result<(), WireError> {
    let initial = cursor.take_one()?;
    let major = initial >> 5;
    let additional_info = initial & 0x1f;

    match major {
        // 0 = unsigned int, 1 = negative int
        0..=1 => {
            read_argument(cursor, additional_info)?;
            Ok(())
        }
        // 2 = byte string
        2 => {
            let len = read_length(cursor, additional_info)?;
            cursor.take(len)?;
            Ok(())
        }
        // 3 = text string: muss gueltiges UTF-8 sein
        3 => {
            let len = read_length(cursor, additional_info)?;
            let raw = cursor.take(len)?;
            core::str::from_utf8(raw).map_err(|_| WireError::InvalidUtf8)?;
            Ok(())
        }
        // 4 = array
        4 => {
            let count = read_length(cursor, additional_info)?;
            let inner = next_depth(depth)?;
            for _ in 0..count {
                validate_item(cursor, inner)?;
            }
            Ok(())
        }
        // 5 = map
        5 => {
            let count = read_length(cursor, additional_info)?;
            let inner = next_depth(depth)?;
            let mut previous_key: Option<&[u8]> = None;
            for _ in 0..count {
                let key_start = cursor.pos;
                validate_item(cursor, inner)?;
                let key = cursor
                    .buf
                    .get(key_start..cursor.pos)
                    .ok_or(WireError::Truncated)?;
                if let Some(previous) = previous_key {
                    // RFC 8949 §4.2.1: bytweise lexikografisch aufsteigend
                    // ueber die deterministischen Kodierungen der Schluessel.
                    match key.cmp(previous) {
                        core::cmp::Ordering::Less => return Err(WireError::MapKeysUnordered),
                        core::cmp::Ordering::Equal => return Err(WireError::DuplicateMapKey),
                        core::cmp::Ordering::Greater => {}
                    }
                }
                previous_key = Some(key);
                validate_item(cursor, inner)?;
            }
            Ok(())
        }
        // 6 = tag
        6 => Err(WireError::TagNotAllowed),
        // 7 = simple values und Gleitkomma
        7 => match additional_info {
            20..=22 => Ok(()), // false, true, null
            25..=27 => Err(WireError::FloatNotAllowed),
            28..=30 => Err(WireError::ReservedAdditionalInfo),
            31 => Err(WireError::IndefiniteLength), // "break" ausserhalb eines Stroms
            _ => Err(WireError::SimpleValueNotAllowed),
        },
        // major stammt aus `initial >> 5` und liegt damit in 0..=7;
        // dieser Arm ist konstruktionsbedingt unerreichbar.
        _ => Err(WireError::ReservedAdditionalInfo),
    }
}

fn next_depth(depth: u32) -> Result<u32, WireError> {
    if depth >= MAX_NESTING_DEPTH {
        return Err(WireError::DepthLimitExceeded);
    }
    Ok(depth.saturating_add(1))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "Testcode"
)]
mod tests {
    use super::*;

    fn err(bytes: &[u8]) -> WireError {
        validate_canonical(bytes).unwrap_err()
    }

    #[test]
    fn kleine_werte_sind_gueltig() {
        validate_canonical(&[0x00]).unwrap(); // 0
        validate_canonical(&[0x17]).unwrap(); // 23
        validate_canonical(&[0x18, 0x18]).unwrap(); // 24
        validate_canonical(&[0x19, 0x01, 0x00]).unwrap(); // 256
        validate_canonical(&[0x1a, 0x00, 0x01, 0x00, 0x00]).unwrap(); // 65536
        validate_canonical(&[0x20]).unwrap(); // -1
    }

    #[test]
    fn nicht_minimale_koepfe() {
        assert_eq!(err(&[0x18, 0x17]), WireError::NonMinimalHead); // 23 in 1 Byte
        assert_eq!(err(&[0x19, 0x00, 0xff]), WireError::NonMinimalHead); // 255 in 2 Byte
        assert_eq!(
            err(&[0x1a, 0x00, 0x00, 0xff, 0xff]),
            WireError::NonMinimalHead
        );
        assert_eq!(
            err(&[0x1b, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff]),
            WireError::NonMinimalHead
        );
    }

    #[test]
    fn unbestimmte_laenge_ist_verboten() {
        assert_eq!(err(&[0x1f]), WireError::IndefiniteLength);
        assert_eq!(err(&[0x5f, 0x41, 0x61, 0xff]), WireError::IndefiniteLength); // bytes*
        assert_eq!(err(&[0x9f, 0x01, 0xff]), WireError::IndefiniteLength); // array*
        assert_eq!(err(&[0xbf, 0x01, 0x01, 0xff]), WireError::IndefiniteLength);
        // map*
    }

    #[test]
    fn reservierte_zusatzinformation() {
        assert_eq!(err(&[0x1c]), WireError::ReservedAdditionalInfo);
        assert_eq!(err(&[0x1e]), WireError::ReservedAdditionalInfo);
    }

    #[test]
    fn byte_und_textstrings() {
        validate_canonical(&[0x43, 0x01, 0x02, 0x03]).unwrap(); // h'010203'
        validate_canonical(&[0x63, 0x61, 0x62, 0x63]).unwrap(); // "abc"
        assert_eq!(err(&[0x43, 0x01, 0x02]), WireError::Truncated);
        assert_eq!(err(&[0x62, 0xff, 0xfe]), WireError::InvalidUtf8);
    }

    #[test]
    fn arrays_und_maps() {
        validate_canonical(&[0x82, 0x01, 0x02]).unwrap(); // [1, 2]
        validate_canonical(&[0xa2, 0x01, 0x01, 0x02, 0x02]).unwrap(); // {1:1, 2:2}
        assert_eq!(err(&[0x82, 0x01]), WireError::Truncated);
    }

    #[test]
    fn map_schluessel_muessen_sortiert_sein() {
        // {2:2, 1:1} — falsche Reihenfolge
        assert_eq!(
            err(&[0xa2, 0x02, 0x02, 0x01, 0x01]),
            WireError::MapKeysUnordered
        );
    }

    #[test]
    fn map_schluessel_muessen_eindeutig_sein() {
        // {1:1, 1:2}
        assert_eq!(
            err(&[0xa2, 0x01, 0x01, 0x01, 0x02]),
            WireError::DuplicateMapKey
        );
    }

    #[test]
    fn laengere_schluessel_sortieren_bytweise() {
        // {"a":0, "b":0} ist korrekt sortiert
        validate_canonical(&[0xa2, 0x61, 0x61, 0x00, 0x61, 0x62, 0x00]).unwrap();
        // {"b":0, "a":0} nicht
        assert_eq!(
            err(&[0xa2, 0x61, 0x62, 0x00, 0x61, 0x61, 0x00]),
            WireError::MapKeysUnordered
        );
    }

    #[test]
    fn tags_sind_verboten() {
        assert_eq!(err(&[0xc0, 0x00]), WireError::TagNotAllowed);
    }

    #[test]
    fn gleitkomma_ist_verboten() {
        assert_eq!(err(&[0xf9, 0x00, 0x00]), WireError::FloatNotAllowed); // f16
        assert_eq!(
            err(&[0xfa, 0x00, 0x00, 0x00, 0x00]),
            WireError::FloatNotAllowed
        ); // f32
        assert_eq!(
            err(&[0xfb, 0, 0, 0, 0, 0, 0, 0, 0]),
            WireError::FloatNotAllowed
        ); // f64
    }

    #[test]
    fn simple_values() {
        validate_canonical(&[0xf4]).unwrap(); // false
        validate_canonical(&[0xf5]).unwrap(); // true
        validate_canonical(&[0xf6]).unwrap(); // null
        assert_eq!(err(&[0xf7]), WireError::SimpleValueNotAllowed); // undefined
        assert_eq!(err(&[0xf0]), WireError::SimpleValueNotAllowed); // simple(16)
        assert_eq!(err(&[0xf8, 0xff]), WireError::SimpleValueNotAllowed);
    }

    #[test]
    fn nachlaufende_bytes() {
        assert_eq!(err(&[0x00, 0x00]), WireError::TrailingBytes);
    }

    #[test]
    fn leere_eingabe() {
        assert_eq!(err(&[]), WireError::Truncated);
    }

    #[test]
    fn tiefenlimit_greift() {
        // MAX_NESTING_DEPTH verschachtelte Arrays sind gueltig ...
        let depth = MAX_NESTING_DEPTH as usize;
        let mut ok = vec![0x81_u8; depth];
        ok.push(0x00);
        validate_canonical(&ok).unwrap();

        // ... eines mehr nicht.
        let mut too_deep = vec![0x81_u8; depth + 1];
        too_deep.push(0x00);
        assert_eq!(
            validate_canonical(&too_deep),
            Err(WireError::DepthLimitExceeded)
        );
    }

    #[test]
    fn riesige_laengenangabe_bricht_nicht_das_speicherbudget() {
        // Array mit 2^32 Elementen, aber ohne Inhalt: muss als Truncated
        // enden, nicht allozieren.
        let bytes = [0x9a, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(err(&bytes), WireError::Truncated);
        // Byte-String mit angeblich 2^32-1 Bytes.
        let bytes = [0x5a, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(err(&bytes), WireError::Truncated);
    }
}
