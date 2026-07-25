//! Fehlertypen von `vault-storage`.
//!
//! Normativ: `spec/engineering-setup.md` §3.1 — Fehler sind explizit typisiert
//! und duerfen keine Rueckschluesse auf Schluesselmaterial oder auf die
//! Existenz eines Kontakts erlauben. Die `Display`-Texte sind deshalb
//! bewusst grob.

use core::fmt;

/// Fehler aus `vault-storage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StorageError {
    /// Der Plattform-Keystore ist nicht erreichbar (ADR-08).
    KeystoreUnavailable,
    /// Der Data-Encryption-Key konnte nicht entsperrt werden.
    DekUnavailable,
    /// Die Datenbank ist gesperrt (App-Passcode / Auto-Lock).
    DatabaseLocked,
    /// Eine Schemamigration ist fehlgeschlagen.
    MigrationFailed,
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::KeystoreUnavailable => "keystore unavailable",
            Self::DekUnavailable => "data encryption key unavailable",
            Self::DatabaseLocked => "database locked",
            Self::MigrationFailed => "migration failed",
        };
        f.write_str(text)
    }
}

impl std::error::Error for StorageError {}
