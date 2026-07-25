//! `vault-delivery` — Sendequeue, Routing, ACK-FSM, Sync-Fenster.
//!
//! Normativ: `spec/gesamtkonzept.md` §2.6, `spec/protokoll-spec.md` §9–§10;
//! ADR-07 (keine Mailbox).
//!
//! **Status:** Geruest. Modulgrenzen und Fehlertypen; keine Implementierung.

#![forbid(unsafe_code)]

pub mod ack_fsm;
pub mod error;
pub mod queue;
pub mod routing;
pub mod sync_window;

pub use error::DeliveryError;
