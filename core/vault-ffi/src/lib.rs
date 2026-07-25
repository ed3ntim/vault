//! `vault-ffi` — Grenze zu Flutter ueber `flutter_rust_bridge`.
//!
//! Normativ: `spec/gesamtkonzept.md` §3; ADR-01; Spike E1.
//!
//! # Ausnahme von forbid(unsafe_code)
//!
//! Dieses Crate ist zusammen mit den Transport-Bindings die einzige nach
//! `spec/engineering-setup.md` §3.1 zugelassene Stelle fuer `unsafe`. Dort
//! gilt: nur mit dokumentiertem Review durch zwei Personen. Gate G-6 fuehrt
//! die Whitelist.
//!
//! Solange keine FFI-Grenze implementiert ist, enthaelt dieses Crate kein
//! `unsafe` — das Attribut unten bleibt deshalb vorerst gesetzt und wird mit
//! der ersten FFI-Signatur (Sprint 0 #6) entfernt.
//!
//! **Status:** Geruest.

#![forbid(unsafe_code)]
