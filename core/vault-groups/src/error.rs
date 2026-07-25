//! Fehlertypen von `vault-groups`.
//!
//! Normativ: `spec/engineering-setup.md` §3.1 — Fehler sind explizit typisiert
//! und duerfen keine Rueckschluesse auf Schluesselmaterial oder auf die
//! Existenz eines Kontakts erlauben. Die `Display`-Texte sind deshalb
//! bewusst grob.

use core::fmt;

/// Fehler aus `vault-groups`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GroupError {
    /// Der Absender ist kein Mitglied dieser Gruppe (gruppen-spec.md §2.1).
    NotAMember,
    /// Die Epoche des Frames passt nicht zum lokalen Gruppenzustand.
    EpochMismatch,
    /// Divergierende Transcript- oder Commit-Hashes erkannt (gruppen-spec.md §5).
    EquivocationDetected,
    /// Der Peer-Sequencer antwortet nicht; Failover laeuft (gruppen-spec.md §4.4).
    SequencerUnavailable,
    /// Das Removal-Quorum ist nicht erreicht (gruppen-spec.md §6.4).
    QuorumNotReached,
}

impl fmt::Display for GroupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::NotAMember => "not a group member",
            Self::EpochMismatch => "epoch mismatch",
            Self::EquivocationDetected => "equivocation detected",
            Self::SequencerUnavailable => "sequencer unavailable",
            Self::QuorumNotReached => "removal quorum not reached",
        };
        f.write_str(text)
    }
}

impl std::error::Error for GroupError {}
