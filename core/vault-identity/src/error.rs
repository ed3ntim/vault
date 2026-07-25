//! Fehlertypen von `vault-identity`.
//!
//! Normativ: `spec/engineering-setup.md` §3.1 — Fehler sind explizit typisiert
//! und duerfen keine Rueckschluesse auf Schluesselmaterial oder auf die
//! Existenz eines Kontakts erlauben. Die `Display`-Texte sind deshalb
//! bewusst grob.

use core::fmt;

/// Fehler aus `vault-identity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentityError {
    /// Eine Quer-Signatur von IK ueber eine Ableitung ist ungueltig (protokoll-spec.md §2).
    CrossSignatureInvalid,
    /// Das angesprochene Kompartiment existiert lokal nicht.
    CompartmentUnknown,
    /// Die Client-Auth-Credential ist lokal nicht bekannt oder revoziert.
    CredentialUnknown,
    /// Die signierte Geraeteliste ist nicht verifizierbar (protokoll-spec.md §9.1).
    DeviceListInvalid,
    /// Die Invitation ist abgelaufen oder die Nonce wurde bereits verwendet.
    InvitationExpired,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::CrossSignatureInvalid => "cross signature invalid",
            Self::CompartmentUnknown => "compartment unknown",
            Self::CredentialUnknown => "credential unknown",
            Self::DeviceListInvalid => "device list invalid",
            Self::InvitationExpired => "invitation not usable",
        };
        f.write_str(text)
    }
}

impl std::error::Error for IdentityError {}
