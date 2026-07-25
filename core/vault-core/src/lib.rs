//! `vault-core` — Orchestrierung und oeffentliche API des Rust-Kerns.
//!
//! Normativ: `spec/gesamtkonzept.md` §3 (Architektur),
//! `spec/engineering-setup.md` §2.
//!
//! **Status:** Geruest. Modulgrenzen und Fehlertypen; keine Implementierung.

#![forbid(unsafe_code)]

pub mod api;
pub mod error;

pub use error::CoreError;
