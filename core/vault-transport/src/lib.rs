//! `vault-transport` — Transport-Trait und die Implementierungen Tor und Mesh.
//!
//! Normativ: `spec/gesamtkonzept.md` §2.5, §2.8, `spec/protokoll-spec.md`
//! §13; ADR-02 (Tor als einziger Internet-Transport), ADR-03.
//!
//! **Schichtregel** (`spec/engineering-setup.md` §2): dieses Crate kennt
//! *keine* Klartext-Payloads. Es transportiert opake Byte-Frames und darf
//! deshalb nicht von `vault-wire`, `vault-crypto` oder hoeheren Schichten
//! abhaengen. Gate G-5 erzwingt das.
//!
//! **Status:** Geruest. Modulgrenzen und Fehlertypen; keine Implementierung.

#![forbid(unsafe_code)]

pub mod error;
pub mod mesh;
pub mod tor;
pub mod transport;

pub use error::TransportError;
