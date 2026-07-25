//! Fehlertypen von `vault-core`.
//!
//! Normativ: `spec/engineering-setup.md` §3.1 — Fehler sind explizit typisiert
//! und duerfen keine Rueckschluesse auf Schluesselmaterial oder auf die
//! Existenz eines Kontakts erlauben. Die `Display`-Texte sind deshalb
//! bewusst grob.

use core::fmt;

/// Fehler aus `vault-core`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoreError {
    /// Der Core wurde noch nicht initialisiert.
    NotInitialized,
    /// Fehler aus der Kryptoschicht.
    Crypto,
    /// Fehler aus der Identitaets- und Kompartimentschicht.
    Identity,
    /// Fehler aus der Wire-Kodierung.
    Wire,
    /// Fehler aus der Transportschicht.
    Transport,
    /// Fehler aus der Zustellschicht.
    Delivery,
    /// Fehler aus der Gruppenschicht.
    Groups,
    /// Fehler aus der Speicherschicht.
    Storage,
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::NotInitialized => "core not initialized",
            Self::Crypto => "crypto layer error",
            Self::Identity => "identity layer error",
            Self::Wire => "wire layer error",
            Self::Transport => "transport layer error",
            Self::Delivery => "delivery layer error",
            Self::Groups => "group layer error",
            Self::Storage => "storage layer error",
        };
        f.write_str(text)
    }
}

impl std::error::Error for CoreError {}
