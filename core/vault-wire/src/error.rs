//! Fehlertypen von `vault-wire`.
//!
//! Normativ: `spec/engineering-setup.md` §3.1 — Fehler sind explizit typisiert
//! und duerfen keine Rueckschluesse auf Schluesselmaterial oder auf die
//! Existenz eines Kontakts erlauben. Die `Display`-Texte sind deshalb
//! bewusst grob.

use core::fmt;

/// Fehler aus `vault-wire`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WireError {
    /// Die Eingabe endet mitten in einem Element.
    Truncated,
    /// Nach dem Element folgen weitere Bytes.
    TrailingBytes,
    /// Der Kopf ist nicht in der kuerzest moeglichen Form kodiert (RFC 8949 §4.2.1).
    NonMinimalHead,
    /// Elemente unbestimmter Laenge sind unzulaessig (protokoll-spec.md §1).
    IndefiniteLength,
    /// Reservierte Zusatzinformation 28..30 im Kopf.
    ReservedAdditionalInfo,
    /// CBOR-Tags sind im Wire-Profil nicht vorgesehen.
    TagNotAllowed,
    /// Gleitkommazahlen sind im Wire-Profil nicht vorgesehen.
    FloatNotAllowed,
    /// Nur `false`, `true` und `null` sind zulaessige Simple Values.
    SimpleValueNotAllowed,
    /// Ein Text-String ist kein gueltiges UTF-8.
    InvalidUtf8,
    /// Map-Schluessel sind nicht bytweise aufsteigend sortiert (RFC 8949 §4.2.1).
    MapKeysUnordered,
    /// Ein Map-Schluessel kommt mehrfach vor.
    DuplicateMapKey,
    /// Die maximale Verschachtelungstiefe wurde ueberschritten.
    DepthLimitExceeded,
    /// Eine Laengenangabe passt nicht in den Adressraum dieser Plattform.
    LengthOverflow,
    /// Ein laengenpraefigiertes Feld ueberschreitet die erlaubte Groesse.
    FieldTooLong,
    /// Der Typ ist noch nicht implementiert (Sprint 0 #3).
    NotImplemented,
    /// An dieser Stelle stand ein anderer CBOR-Typ als erwartet.
    UnexpectedType,
    /// Ein Wert passt nicht in den Zieltyp oder hat die falsche Laenge.
    ValueOutOfRange,
    /// Ein Pflichtfeld fehlt oder ein Feldschluessel ist unbekannt.
    FieldMismatch,
    /// Die Versionsnummer der Struktur wird nicht unterstuetzt.
    UnsupportedVersion,
    /// Unbekannte Variante eines Summentyps (z. B. `Payload`).
    UnknownVariant,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Truncated => "truncated input",
            Self::TrailingBytes => "trailing bytes",
            Self::NonMinimalHead => "non-minimal head encoding",
            Self::IndefiniteLength => "indefinite length item",
            Self::ReservedAdditionalInfo => "reserved additional information",
            Self::TagNotAllowed => "tag not allowed",
            Self::FloatNotAllowed => "float not allowed",
            Self::SimpleValueNotAllowed => "simple value not allowed",
            Self::InvalidUtf8 => "invalid utf-8 text string",
            Self::MapKeysUnordered => "map keys unordered",
            Self::DuplicateMapKey => "duplicate map key",
            Self::DepthLimitExceeded => "nesting depth limit exceeded",
            Self::LengthOverflow => "length overflow",
            Self::FieldTooLong => "field too long",
            Self::NotImplemented => "not implemented",
            Self::UnexpectedType => "unexpected cbor type",
            Self::ValueOutOfRange => "value out of range",
            Self::FieldMismatch => "field mismatch",
            Self::UnsupportedVersion => "unsupported version",
            Self::UnknownVariant => "unknown variant",
        };
        f.write_str(text)
    }
}

impl std::error::Error for WireError {}
