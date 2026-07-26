//! Deterministischer CBOR-Encoder und -Decoder.
//!
//! Normativ: `spec/protokoll-spec.md` §1 („Wire-Kodierung: **CBOR**
//! (deterministisch, RFC 8949 §4.2). Kein Feld ohne explizite Länge."),
//! ADR-11.
//!
//! Der Encoder erzeugt **ausschließlich** deterministische Kodierung:
//! kürzest möglicher Kopf, keine unbestimmten Längen, Map-Schlüssel bytweise
//! aufsteigend und duplikatfrei. Der Decoder prüft die Eingabe vor dem ersten
//! Feldzugriff mit [`crate::cbor::validate_canonical`] — nicht-kanonische
//! Bytes werden also abgewiesen, statt tolerant gelesen zu werden. Das ist
//! Voraussetzung dafür, dass Signaturen über CBOR-Strukturen
//! plattformübergreifend konsistent sind (Spike S7).
//!
//! Bewusst ohne externe Bibliothek: **GATE-6** („Wire-Format final
//! (CBOR-Profil)") ist offen, Spike S7 nicht gelaufen. Eine Bibliothekswahl
//! jetzt würde das Gate vorwegnehmen.

use crate::cbor;
use crate::error::WireError;

/// Baut deterministisch kodiertes CBOR auf.
#[derive(Debug, Default, Clone)]
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    /// Neuer, leerer Encoder.
    #[must_use]
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    fn head(&mut self, major: u8, argument: u64) {
        let mt = major << 5;
        if argument <= 23 {
            #[allow(clippy::cast_possible_truncation, reason = "argument <= 23")]
            self.buf.push(mt | argument as u8);
        } else if let Ok(v) = u8::try_from(argument) {
            self.buf.push(mt | 24);
            self.buf.push(v);
        } else if let Ok(v) = u16::try_from(argument) {
            self.buf.push(mt | 25);
            self.buf.extend_from_slice(&v.to_be_bytes());
        } else if let Ok(v) = u32::try_from(argument) {
            self.buf.push(mt | 26);
            self.buf.extend_from_slice(&v.to_be_bytes());
        } else {
            self.buf.push(mt | 27);
            self.buf.extend_from_slice(&argument.to_be_bytes());
        }
    }

    /// Vorzeichenlose Ganzzahl (Major Type 0).
    pub fn u64(&mut self, value: u64) {
        self.head(0, value);
    }

    /// Byte-String (Major Type 2).
    pub fn bytes(&mut self, value: &[u8]) {
        self.head(2, value.len() as u64);
        self.buf.extend_from_slice(value);
    }

    /// Text-String (Major Type 3).
    pub fn text(&mut self, value: &str) {
        self.head(3, value.len() as u64);
        self.buf.extend_from_slice(value.as_bytes());
    }

    /// Array-Kopf mit `len` folgenden Elementen (Major Type 4).
    pub fn array(&mut self, len: usize) {
        self.head(4, len as u64);
    }

    /// Map-Kopf mit `len` folgenden Schlüssel-Wert-Paaren (Major Type 5).
    ///
    /// Der Aufrufer ist dafür verantwortlich, die Schlüssel bytweise
    /// aufsteigend zu schreiben. Bei den hier verwendeten
    /// `u64`-Schlüsseln 0,1,2,… ist die numerische Reihenfolge zugleich die
    /// bytweise; [`Encoder::finish`] prüft das Ergebnis ohnehin.
    pub fn map(&mut self, len: usize) {
        self.head(5, len as u64);
    }

    /// `false` / `true` (Major Type 7).
    pub fn bool(&mut self, value: bool) {
        self.buf.push(if value { 0xf5 } else { 0xf4 });
    }

    /// `null` (Major Type 7).
    pub fn null(&mut self) {
        self.buf.push(0xf6);
    }

    /// Schließt ab und prüft das Ergebnis auf Kanonizität.
    ///
    /// # Fehler
    ///
    /// Jeder Fehler aus [`crate::cbor::validate_canonical`]. Ein Fehler hier
    /// bedeutet einen Fehler im aufrufenden Serialisierungscode (z. B.
    /// falsche Elementzahl im Kopf oder unsortierte Map-Schlüssel) und darf
    /// nie auf die Wire gelangen.
    pub fn finish(self) -> Result<Vec<u8>, WireError> {
        cbor::validate_canonical(&self.buf)?;
        Ok(self.buf)
    }

    /// Bisher geschriebene Bytes, ohne Prüfung.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }
}

/// Liest deterministisch kodiertes CBOR.
///
/// [`Decoder::new`] validiert die gesamte Eingabe vorab; danach greifen die
/// Lesefunktionen auf bereits geprüfte Bytes zu.
#[derive(Debug)]
pub struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    /// Neuer Decoder über `input`.
    ///
    /// # Fehler
    ///
    /// Jeder Fehler aus [`crate::cbor::validate_canonical`] — insbesondere
    /// nicht-minimale Köpfe, unbestimmte Längen, unsortierte oder doppelte
    /// Map-Schlüssel.
    pub fn new(input: &'a [u8]) -> Result<Self, WireError> {
        cbor::validate_canonical(input)?;
        Ok(Self { input, pos: 0 })
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::LengthOverflow)?;
        let slice = self.input.get(self.pos..end).ok_or(WireError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn head(&mut self, expected_major: u8) -> Result<u64, WireError> {
        let initial = *self.input.get(self.pos).ok_or(WireError::Truncated)?;
        self.pos = self.pos.checked_add(1).ok_or(WireError::LengthOverflow)?;
        let major = initial >> 5;
        if major != expected_major {
            return Err(WireError::UnexpectedType);
        }
        let ai = initial & 0x1f;
        match ai {
            0..=23 => Ok(u64::from(ai)),
            24 => Ok(u64::from(
                *self.take(1)?.first().ok_or(WireError::Truncated)?,
            )),
            25 => {
                let raw: [u8; 2] = self.take(2)?.try_into().map_err(|_| WireError::Truncated)?;
                Ok(u64::from(u16::from_be_bytes(raw)))
            }
            26 => {
                let raw: [u8; 4] = self.take(4)?.try_into().map_err(|_| WireError::Truncated)?;
                Ok(u64::from(u32::from_be_bytes(raw)))
            }
            27 => {
                let raw: [u8; 8] = self.take(8)?.try_into().map_err(|_| WireError::Truncated)?;
                Ok(u64::from_be_bytes(raw))
            }
            _ => Err(WireError::ReservedAdditionalInfo),
        }
    }

    /// Liest eine vorzeichenlose Ganzzahl.
    ///
    /// # Fehler
    ///
    /// [`WireError::UnexpectedType`], wenn an dieser Stelle kein `uint` steht.
    pub fn u64(&mut self) -> Result<u64, WireError> {
        self.head(0)
    }

    /// Liest eine Ganzzahl und engt sie auf `u32` ein.
    ///
    /// # Fehler
    ///
    /// [`WireError::ValueOutOfRange`], wenn der Wert nicht in `u32` passt.
    pub fn u32(&mut self) -> Result<u32, WireError> {
        u32::try_from(self.u64()?).map_err(|_| WireError::ValueOutOfRange)
    }

    /// Liest einen Byte-String.
    ///
    /// # Fehler
    ///
    /// [`WireError::UnexpectedType`] oder [`WireError::Truncated`].
    pub fn bytes(&mut self) -> Result<&'a [u8], WireError> {
        let len = self.head(2)?;
        let len = usize::try_from(len).map_err(|_| WireError::LengthOverflow)?;
        self.take(len)
    }

    /// Liest einen Byte-String fester Länge.
    ///
    /// # Fehler
    ///
    /// [`WireError::ValueOutOfRange`], wenn die Länge nicht passt.
    pub fn byte_array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let raw = self.bytes()?;
        raw.try_into().map_err(|_| WireError::ValueOutOfRange)
    }

    /// Liest `null` oder einen Byte-String.
    ///
    /// # Fehler
    ///
    /// [`WireError::UnexpectedType`], wenn dort weder `null` noch ein
    /// Byte-String steht.
    pub fn optional_bytes(&mut self) -> Result<Option<&'a [u8]>, WireError> {
        if *self.input.get(self.pos).ok_or(WireError::Truncated)? == 0xf6 {
            self.pos = self.pos.checked_add(1).ok_or(WireError::LengthOverflow)?;
            return Ok(None);
        }
        self.bytes().map(Some)
    }

    /// Liest `null` oder einen Byte-String fester Länge.
    ///
    /// # Fehler
    ///
    /// Wie [`Decoder::optional_bytes`], zusätzlich
    /// [`WireError::ValueOutOfRange`] bei falscher Länge.
    pub fn optional_byte_array<const N: usize>(&mut self) -> Result<Option<[u8; N]>, WireError> {
        match self.optional_bytes()? {
            None => Ok(None),
            Some(raw) => raw
                .try_into()
                .map(Some)
                .map_err(|_| WireError::ValueOutOfRange),
        }
    }

    /// Liest einen Text-String.
    ///
    /// # Fehler
    ///
    /// [`WireError::UnexpectedType`], [`WireError::Truncated`] oder
    /// [`WireError::InvalidUtf8`].
    pub fn text(&mut self) -> Result<&'a str, WireError> {
        let len = self.head(3)?;
        let len = usize::try_from(len).map_err(|_| WireError::LengthOverflow)?;
        let raw = self.take(len)?;
        core::str::from_utf8(raw).map_err(|_| WireError::InvalidUtf8)
    }

    /// Liest einen Array-Kopf und liefert die Elementzahl.
    ///
    /// # Fehler
    ///
    /// [`WireError::UnexpectedType`].
    pub fn array_len(&mut self) -> Result<usize, WireError> {
        let len = self.head(4)?;
        usize::try_from(len).map_err(|_| WireError::LengthOverflow)
    }

    /// Liest einen Map-Kopf und liefert die Paarzahl.
    ///
    /// # Fehler
    ///
    /// [`WireError::UnexpectedType`].
    pub fn map_len(&mut self) -> Result<usize, WireError> {
        let len = self.head(5)?;
        usize::try_from(len).map_err(|_| WireError::LengthOverflow)
    }

    /// Prüft, dass die Eingabe vollständig gelesen wurde.
    ///
    /// # Fehler
    ///
    /// [`WireError::TrailingBytes`].
    pub fn finish(self) -> Result<(), WireError> {
        if self.pos == self.input.len() {
            Ok(())
        } else {
            Err(WireError::TrailingBytes)
        }
    }
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

    #[test]
    fn koepfe_sind_minimal_kodiert() {
        let mut e = Encoder::new();
        e.u64(23);
        assert_eq!(e.as_bytes(), &[0x17]);

        let mut e = Encoder::new();
        e.u64(24);
        assert_eq!(e.as_bytes(), &[0x18, 0x18]);

        let mut e = Encoder::new();
        e.u64(256);
        assert_eq!(e.as_bytes(), &[0x19, 0x01, 0x00]);

        let mut e = Encoder::new();
        e.u64(u64::from(u32::MAX) + 1);
        assert_eq!(e.as_bytes()[0], 0x1b);
    }

    #[test]
    fn roundtrip_grundtypen() {
        let mut e = Encoder::new();
        e.array(4);
        e.u64(42);
        e.bytes(&[1, 2, 3]);
        e.text("privat");
        e.bool(true);
        let bytes = e.finish().unwrap();

        let mut d = Decoder::new(&bytes).unwrap();
        assert_eq!(d.array_len().unwrap(), 4);
        assert_eq!(d.u64().unwrap(), 42);
        assert_eq!(d.bytes().unwrap(), &[1, 2, 3]);
        assert_eq!(d.text().unwrap(), "privat");
    }

    #[test]
    fn determinismus_ueber_wiederholte_laeufe() {
        let baue = || {
            let mut e = Encoder::new();
            e.map(3);
            e.u64(0);
            e.u64(1);
            e.u64(1);
            e.bytes(&[0xaa; 32]);
            e.u64(2);
            e.text("beruflich");
            e.finish().unwrap()
        };
        let erste = baue();
        for _ in 0..100 {
            assert_eq!(baue(), erste, "gleiche Struktur muss bitidentisch sein");
        }
    }

    #[test]
    fn encoder_weist_unsortierte_map_schluessel_ab() {
        let mut e = Encoder::new();
        e.map(2);
        e.u64(2);
        e.u64(0);
        e.u64(1);
        e.u64(0);
        assert_eq!(e.finish(), Err(WireError::MapKeysUnordered));
    }

    #[test]
    fn encoder_weist_falsche_elementzahl_ab() {
        let mut e = Encoder::new();
        e.array(3);
        e.u64(1);
        assert_eq!(e.finish(), Err(WireError::Truncated));
    }

    #[test]
    fn decoder_weist_nicht_kanonische_eingabe_ab() {
        // 23 in Zwei-Byte-Form kodiert — gueltiges CBOR, aber nicht kanonisch.
        assert_eq!(
            Decoder::new(&[0x18, 0x17]).map(|_| ()),
            Err(WireError::NonMinimalHead)
        );
    }

    #[test]
    fn decoder_meldet_falschen_typ() {
        let mut e = Encoder::new();
        e.text("kein uint");
        let bytes = e.finish().unwrap();
        let mut d = Decoder::new(&bytes).unwrap();
        assert_eq!(d.u64(), Err(WireError::UnexpectedType));
    }

    #[test]
    fn byte_array_prueft_die_laenge() {
        let mut e = Encoder::new();
        e.bytes(&[7u8; 16]);
        let bytes = e.finish().unwrap();

        let mut d = Decoder::new(&bytes).unwrap();
        assert!(d.byte_array::<32>().is_err());

        let mut d = Decoder::new(&bytes).unwrap();
        assert_eq!(d.byte_array::<16>().unwrap(), [7u8; 16]);
    }

    #[test]
    fn u32_engt_ein() {
        let mut e = Encoder::new();
        e.u64(u64::from(u32::MAX) + 1);
        let bytes = e.finish().unwrap();
        let mut d = Decoder::new(&bytes).unwrap();
        assert_eq!(d.u32(), Err(WireError::ValueOutOfRange));
    }

    #[test]
    fn finish_meldet_restbytes() {
        let mut e = Encoder::new();
        e.array(2);
        e.u64(1);
        e.u64(2);
        let bytes = e.finish().unwrap();
        let mut d = Decoder::new(&bytes).unwrap();
        assert_eq!(d.array_len().unwrap(), 2);
        assert_eq!(d.u64().unwrap(), 1);
        assert_eq!(d.finish(), Err(WireError::TrailingBytes));
    }
}
