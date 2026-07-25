//! `vault-storage` — SQLCipher, Migrationen, Keystore-Adapter.
//!
//! Normativ: `spec/gesamtkonzept.md` §2.10; ADR-08 (DEK im Plattform-Keystore,
//! Crypto-Erase); Spike E2.
//!
//! **Status:** Geruest. Modulgrenzen und Fehlertypen; keine Implementierung.

#![forbid(unsafe_code)]

pub mod db;
pub mod error;
pub mod keystore;
pub mod migrations;

pub use error::StorageError;
