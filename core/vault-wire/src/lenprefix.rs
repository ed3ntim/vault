//! Laengenpraefigierte Byte-Konkatenation (`‖`).
//!
//! Normativ: `spec/protokoll-spec.md` §1 — „`‖` Byte-Konkatenation mit
//! Laengenpraefix", „Alle Multi-Byte-Felder little-endian", „Kein Feld ohne
//! explizite Laenge".
//!
//! Verwendung: eindeutige Serialisierung zusammengesetzter Signatur-Eingaben
//! (z. B. `Sig(ik_ed_priv, osk_ed_pub ‖ id)`, `spec/protokoll-spec.md` §3).
//! Ohne Laengenpraefix waeren zwei verschiedene Feldfolgen auf dieselben
//! Bytes abbildbar — genau der Fehler, der Signaturen verwechselbar macht.
//!
//! Kodierung eines Feldes: `u32` Laenge little-endian, dann die Bytes.

use crate::error::WireError;

/// Groesse des Laengenpraefixes in Bytes.
pub const LENGTH_PREFIX_BYTES: usize = 4;

/// Baut eine laengenpraefigierte Feldfolge auf.
#[derive(Debug, Default, Clone)]
pub struct FieldWriter {
    buf: Vec<u8>,
}

impl FieldWriter {
    /// Neuer, leerer Writer.
    #[must_use]
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Haengt ein Feld an.
    ///
    /// # Fehler
    ///
    /// [`WireError::FieldTooLong`], wenn das Feld nicht in ein `u32`-Praefix
    /// passt.
    pub fn push(&mut self, field: &[u8]) -> Result<(), WireError> {
        let len = u32::try_from(field.len()).map_err(|_| WireError::FieldTooLong)?;
        self.buf.extend_from_slice(&len.to_le_bytes());
        self.buf.extend_from_slice(field);
        Ok(())
    }

    /// Bisher geschriebene Bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Gibt die geschriebenen Bytes zurueck.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

/// Liest eine laengenpraefigierte Feldfolge.
///
/// Der Reader kopiert nichts; er gibt Slices in die Eingabe zurueck.
#[derive(Debug, Clone)]
pub struct FieldReader<'a> {
    rest: &'a [u8],
    max_field_len: usize,
}

impl<'a> FieldReader<'a> {
    /// Neuer Reader ueber `input`.
    ///
    /// `max_field_len` begrenzt die akzeptierte Feldgroesse. Die Grenze
    /// gehoert zum jeweiligen Nachrichtentyp und wird deshalb vom Aufrufer
    /// gesetzt, nicht hier festgelegt.
    #[must_use]
    pub fn new(input: &'a [u8], max_field_len: usize) -> Self {
        Self {
            rest: input,
            max_field_len,
        }
    }

    /// Liefert das naechste Feld oder `None` am Ende der Eingabe.
    ///
    /// # Fehler
    ///
    /// * [`WireError::Truncated`] — Praefix oder Feld reichen nicht aus.
    /// * [`WireError::FieldTooLong`] — Feld ueberschreitet `max_field_len`.
    /// * [`WireError::LengthOverflow`] — Laenge passt nicht in `usize`.
    pub fn next_field(&mut self) -> Result<Option<&'a [u8]>, WireError> {
        if self.rest.is_empty() {
            return Ok(None);
        }
        let (prefix, after_prefix) = self
            .rest
            .split_at_checked(LENGTH_PREFIX_BYTES)
            .ok_or(WireError::Truncated)?;
        let raw: [u8; LENGTH_PREFIX_BYTES] = prefix.try_into().map_err(|_| WireError::Truncated)?;
        let len =
            usize::try_from(u32::from_le_bytes(raw)).map_err(|_| WireError::LengthOverflow)?;
        if len > self.max_field_len {
            return Err(WireError::FieldTooLong);
        }
        let (field, tail) = after_prefix
            .split_at_checked(len)
            .ok_or(WireError::Truncated)?;
        self.rest = tail;
        Ok(Some(field))
    }

    /// Noch nicht gelesene Bytes.
    #[must_use]
    pub fn remaining(&self) -> &'a [u8] {
        self.rest
    }

    /// Schliesst den Reader ab.
    ///
    /// # Fehler
    ///
    /// [`WireError::TrailingBytes`], wenn noch Bytes uebrig sind.
    pub fn finish(self) -> Result<(), WireError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(WireError::TrailingBytes)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "Testcode")]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_mehrere_felder() {
        let mut w = FieldWriter::new();
        w.push(b"").unwrap();
        w.push(b"osk_ed_pub").unwrap();
        w.push(&[0x00, 0xff, 0x7f]).unwrap();
        let bytes = w.into_bytes();

        let mut r = FieldReader::new(&bytes, 1024);
        assert_eq!(r.next_field().unwrap(), Some(&b""[..]));
        assert_eq!(r.next_field().unwrap(), Some(&b"osk_ed_pub"[..]));
        assert_eq!(r.next_field().unwrap(), Some(&[0x00, 0xff, 0x7f][..]));
        assert_eq!(r.next_field().unwrap(), None);
        r.finish().unwrap();
    }

    #[test]
    fn unterschiedliche_feldgrenzen_erzeugen_unterschiedliche_bytes() {
        // Genau die Verwechslung, die das Laengenpraefix verhindern soll.
        let mut a = FieldWriter::new();
        a.push(b"ab").unwrap();
        a.push(b"c").unwrap();
        let mut b = FieldWriter::new();
        b.push(b"a").unwrap();
        b.push(b"bc").unwrap();
        assert_ne!(a.into_bytes(), b.into_bytes());
    }

    #[test]
    fn abgeschnittenes_praefix() {
        let mut r = FieldReader::new(&[0x01, 0x00], 1024);
        assert_eq!(r.next_field(), Err(WireError::Truncated));
    }

    #[test]
    fn abgeschnittenes_feld() {
        let mut r = FieldReader::new(&[0x04, 0x00, 0x00, 0x00, 0xaa], 1024);
        assert_eq!(r.next_field(), Err(WireError::Truncated));
    }

    #[test]
    fn feld_ueber_grenze() {
        let mut r = FieldReader::new(&[0x10, 0x00, 0x00, 0x00], 8);
        assert_eq!(r.next_field(), Err(WireError::FieldTooLong));
    }

    #[test]
    fn restbytes_werden_gemeldet() {
        let mut w = FieldWriter::new();
        w.push(b"x").unwrap();
        let mut bytes = w.into_bytes();
        bytes.push(0x00);
        let mut r = FieldReader::new(&bytes, 16);
        let _ = r.next_field().unwrap();
        assert_eq!(r.finish(), Err(WireError::TrailingBytes));
    }
}
