//! `vault-groups` — MLS-Wrapper, Peer-Sequencer, Attestation, Pairwise-Fanout.
//!
//! Normativ: `spec/gruppen-spec.md` (vollstaendig), `spec/gesamtkonzept.md`
//! §2.7, `spec/protokoll-spec.md` §12; ADR-06.
//!
//! **Status:** Geruest. Ob Gruppen in Phase 1 enthalten sind, entscheidet
//! GATE-4 auf Basis der Spikes G1 und G2.

#![forbid(unsafe_code)]

pub mod attestation;
pub mod error;
pub mod mls;
pub mod pairwise;
pub mod sequencer;

pub use error::GroupError;
