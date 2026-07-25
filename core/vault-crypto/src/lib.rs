//! `vault-crypto` — Wrapper um die kryptografischen Verfahren aus ADR-05.
//!
//! Normativ: `spec/gesamtkonzept.md` §2.4, `spec/protokoll-spec.md` §1–§2,
//! ADR-05 (PQXDH + Double Ratchet, keine Eigenentwicklung).
//!
//! **Schichtregel** (`spec/engineering-setup.md` §2): dieses Crate hat *keine*
//! I/O- und *keine* Netzabhaengigkeiten. Gate G-5 erzwingt das.
//!
//! **Status:** Geruest. Es existieren ausschliesslich Modulgrenzen und
//! Fehlertypen. Die Verfahren werden nach ADR-05 ueber etablierte
//! Bibliotheken eingefuehrt (Sprint 0 #4). Platzhalter-Krypto ist nach
//! `CLAUDE.md` ausdruecklich verboten und daher nicht vorhanden.

#![forbid(unsafe_code)]

pub mod aead;
pub mod error;
pub mod kdf;
pub mod pqxdh;
pub mod ratchet;

pub use error::CryptoError;
