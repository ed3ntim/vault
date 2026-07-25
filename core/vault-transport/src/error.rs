//! Fehlertypen von `vault-transport`.
//!
//! Normativ: `spec/engineering-setup.md` §3.1 — Fehler sind explizit typisiert
//! und duerfen keine Rueckschluesse auf Schluesselmaterial oder auf die
//! Existenz eines Kontakts erlauben. Die `Display`-Texte sind deshalb
//! bewusst grob.

use core::fmt;

/// Fehler aus `vault-transport`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportError {
    /// Es besteht keine Transportverbindung.
    NotConnected,
    /// Der Transport wurde ohne Pflicht-Client-Auth angefordert (ADR-03, TR-1).
    ClientAuthRequired,
    /// Der uebergebene opake Frame ueberschreitet die Groessengrenze.
    FrameTooLarge,
    /// Der Transportkanal ist derzeit nicht verfuegbar.
    TransportUnavailable,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::NotConnected => "not connected",
            Self::ClientAuthRequired => "client authorization required",
            Self::FrameTooLarge => "frame too large",
            Self::TransportUnavailable => "transport unavailable",
        };
        f.write_str(text)
    }
}

impl std::error::Error for TransportError {}
