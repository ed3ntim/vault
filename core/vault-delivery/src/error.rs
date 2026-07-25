//! Fehlertypen von `vault-delivery`.
//!
//! Normativ: `spec/engineering-setup.md` §3.1 — Fehler sind explizit typisiert
//! und duerfen keine Rueckschluesse auf Schluesselmaterial oder auf die
//! Existenz eines Kontakts erlauben. Die `Display`-Texte sind deshalb
//! bewusst grob.

use core::fmt;

/// Fehler aus `vault-delivery`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeliveryError {
    /// Die persistente Ausgangswarteschlange ist voll (DL-1).
    QueueFull,
    /// Kein Geraet des Empfaengers ist derzeit erreichbar (DL-2).
    NoReachableDevice,
    /// Ein empfangenes E2E-ACK passt zu keiner wartenden Nachricht (DL-5).
    AckMismatch,
    /// Unzulaessiger Uebergang in der Zustellstatus-FSM (protokoll-spec.md §9.4).
    InvalidStateTransition,
}

impl fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::QueueFull => "outbound queue full",
            Self::NoReachableDevice => "no reachable device",
            Self::AckMismatch => "ack does not match",
            Self::InvalidStateTransition => "invalid delivery state transition",
        };
        f.write_str(text)
    }
}

impl std::error::Error for DeliveryError {}
