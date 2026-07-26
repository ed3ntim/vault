//! `vault-crypto` — Wrapper um die kryptografischen Verfahren aus ADR-05.
//!
//! Normativ: `spec/gesamtkonzept.md` §2.4, `spec/protokoll-spec.md` §1–§2,
//! §5, §8; ADR-05 (PQXDH + Double Ratchet, keine Eigenentwicklung).
//!
//! **Schichtregel** (`spec/engineering-setup.md` §2): dieses Crate hat *keine*
//! I/O- und *keine* Netzabhaengigkeiten. Gate G-5 erzwingt das. Insbesondere
//! erzeugt es **keine** Zufallszahlen: die Schluesselerzeugung unterliegt dem
//! Entropie-Gate (`gesamtkonzept.md` §2.1, ID-2) und gehoert nach
//! `vault-identity`. Alle Typen hier werden aus vorhandenen Bytes gebildet.
//!
//! **Stand der Umsetzung:**
//!
//! | Modul | Verfahren (§1) | Stand |
//! |---|---|---|
//! | [`kdf`] | HKDF-SHA-256, `KDF_RK`, `KDF_CK` | implementiert |
//! | [`hash`] | `H(x)` = BLAKE3-256 | implementiert |
//! | [`aead`] | XChaCha20-Poly1305 | implementiert |
//! | [`sign`] | Ed25519 | implementiert |
//! | [`dh`] | X25519 | implementiert |
//! | [`ratchet`] | Double Ratchet (§8) | implementiert |
//! | [`pqxdh`] | PQXDH (§5) | klassischer Anteil implementiert, **ML-KEM fehlt** |
//!
//! Der fehlende ML-KEM-Anteil ist in [`pqxdh`] dokumentiert. Bis er vorliegt,
//! ist PQXDH nicht einsatzfaehig — Platzhalter-Krypto ist nach `CLAUDE.md`
//! verboten und daher nicht vorhanden.

#![forbid(unsafe_code)]

pub mod aead;
pub mod dh;
pub mod error;
pub mod hash;
pub mod kdf;
pub mod pqxdh;
pub mod ratchet;
pub mod sign;

pub use error::CryptoError;
