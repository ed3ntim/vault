//! `vault-identity` — Identitaet, Kompartimente, Credentials, Geraeteliste.
//!
//! Normativ: `spec/gesamtkonzept.md` §2.1–§2.2, `spec/protokoll-spec.md`
//! §2–§6, §11; ADR-03, ADR-04.
//!
//! **Status:** Geruest. Modulgrenzen und Fehlertypen; keine Implementierung.

#![forbid(unsafe_code)]

pub mod compartment;
pub mod credential;
pub mod device;
pub mod error;
pub mod identity;

pub use error::IdentityError;
