//! `vault-wire` — Wire-Format: deterministisches CBOR und laengenpraefigierte
//! Felder.
//!
//! Normativ: `spec/protokoll-spec.md` §1 („Wire-Kodierung: **CBOR**
//! (deterministisch, RFC 8949 §4.2). Kein Feld ohne explizite Laenge.",
//! „`‖` Byte-Konkatenation mit Laengenpraefix"), ADR-11.
//!
//! **Status.** Zwei Bausteine sind implementiert und getestet:
//!
//! * [`cbor::validate_canonical`] — prueft einen Byte-Slice auf
//!   Wohlgeformtheit *und* auf die deterministische Kodierung nach
//!   RFC 8949 §4.2.
//! * [`lenprefix`] — strikter Encoder/Decoder fuer laengenpraefigierte
//!   Felder, wie sie als Signatur-Eingabe gebraucht werden.
//!
//! Beides ist bewusst ohne externe Abhaengigkeit gebaut: Spike S7
//! (`spec/phase0-spikeplan.md`) ist nicht gelaufen und **GATE-6**
//! („Wire-Format final (CBOR-Profil)") ist offen. Ein Validator ueber rohe
//! Bytes nimmt diese Entscheidung nicht vorweg und wird auch dann noch
//! gebraucht, wenn die Kodierung selbst aus einer Bibliothek kommt.
//! CBOR ist kein Kryptoprimitiv — die Eigenbau-Sperre aus ADR-05 ist nicht
//! beruehrt.
//!
//! Darauf aufbauend:
//!
//! * [`codec`] — deterministischer CBOR-Encoder und -Decoder. Der Decoder
//!   validiert die Eingabe vorab; nicht-kanonische Bytes werden abgewiesen,
//!   statt tolerant gelesen zu werden.
//! * [`invitation`] — `Invitation` nach §4.
//! * [`envelope`] — `Envelope` und `Payload` nach §8.
//!
//! Offen: `GroupFrame` (§12) und `Attestation` (`spec/gruppen-spec.md` §5).
//! Die Feldnummerierung der CBOR-Maps ist eine Implementierungsfestlegung —
//! **GATE-6** („Wire-Format final") ist nicht entschieden.

#![forbid(unsafe_code)]

pub mod attestation;
pub mod cbor;
pub mod codec;
pub mod envelope;
pub mod error;
pub mod group_frame;
pub mod invitation;
pub mod lenprefix;

pub use error::WireError;
