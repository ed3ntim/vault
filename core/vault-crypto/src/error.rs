//! Fehlertypen von `vault-crypto`.
//!
//! Normativ: `spec/engineering-setup.md` §3.1 — Fehler sind explizit typisiert
//! und duerfen keine Rueckschluesse auf Schluesselmaterial oder auf die
//! Existenz eines Kontakts erlauben. Die `Display`-Texte sind deshalb
//! bewusst grob.

use core::fmt;

/// Fehler aus `vault-crypto`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    /// Das Entropie-Gate wurde nicht erfuellt (gesamtkonzept.md §2.1, ID-2).
    InsufficientEntropy,
    /// Ein uebergebenes Schluesselmaterial hat eine unzulaessige Laenge.
    InvalidKeyLength,
    /// AEAD-Entschluesselung oder -Verifikation fehlgeschlagen.
    AeadOpenFailed,
    /// Der Double-Ratchet-Zustand ist inkonsistent.
    RatchetStateInvalid,
    /// Obergrenze fuer `skipped_message_keys` erreicht (phase0-spikeplan.md S2).
    SkippedKeyLimitExceeded,
    /// AEAD-Verschluesselung fehlgeschlagen.
    AeadSealFailed,
    /// Signatur oder Verifikationsschluessel ungueltig. Die beiden Faelle
    /// werden bewusst nicht unterschieden.
    SignatureInvalid,
    /// Zu der Nachricht existiert kein Message Key mehr — entweder bereits
    /// verbraucht (Forward Secrecy) oder nie vorhanden.
    MessageKeyUnavailable,
    /// Der Post-Quantum-KEM-Anteil von PQXDH ist noch nicht implementiert
    /// (ADR-05, ML-KEM-768). Siehe `pqxdh`-Moduldokumentation.
    KemNotImplemented,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::InsufficientEntropy => "entropy gate not satisfied",
            Self::InvalidKeyLength => "invalid key material length",
            Self::AeadOpenFailed => "aead open failed",
            Self::RatchetStateInvalid => "ratchet state invalid",
            Self::SkippedKeyLimitExceeded => "skipped key limit exceeded",
            Self::AeadSealFailed => "aead seal failed",
            Self::SignatureInvalid => "signature invalid",
            Self::MessageKeyUnavailable => "message key unavailable",
            Self::KemNotImplemented => "kem not implemented",
        };
        f.write_str(text)
    }
}

impl std::error::Error for CryptoError {}
