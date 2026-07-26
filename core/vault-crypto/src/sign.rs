//! Ed25519 — Signatur und Verifikation.
//!
//! Normativ: `spec/protokoll-spec.md` §1 („`Sig(sk, m)` / `Vrf(pk, m, σ)` —
//! Ed25519"), §2 (IK signiert alle Ableitungen), §4 (`Invitation.sig`).
//! ADR-05: Bibliothek `ed25519-dalek`.
//!
//! Wie in [`crate::dh`] wird hier **kein** Schlüssel aus Zufall erzeugt —
//! das unterliegt dem Entropie-Gate und gehört nach `vault-identity`.
//!
//! `spec/gesamtkonzept.md` §2.4 bevorzugt abstreitbare MACs gegenüber
//! Signaturen, „wo möglich". Signaturen bleiben dort nötig, wo ein Dritter
//! prüfen können muss: Quer-Signaturen der Schlüsselhierarchie (§2),
//! Invitation (§4), Geräteliste (§9.1).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

/// Länge eines Ed25519-Schlüssels in Bytes.
pub const ED25519_KEY_LEN: usize = 32;

/// Länge einer Ed25519-Signatur in Bytes.
pub const ED25519_SIG_LEN: usize = 64;

/// Privater Ed25519-Signaturschlüssel.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SigningPrivate([u8; ED25519_KEY_LEN]);

/// Öffentlicher Ed25519-Verifikationsschlüssel.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifyingPublic([u8; ED25519_KEY_LEN]);

impl core::fmt::Debug for SigningPrivate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SigningPrivate(redacted)")
    }
}

impl core::fmt::Debug for VerifyingPublic {
    /// Der öffentliche Identitätsschlüssel ist zugleich die Onion-Adresse
    /// (`gesamtkonzept.md` §2.1) und darf nicht in Logs landen.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("VerifyingPublic(redacted)")
    }
}

impl SigningPrivate {
    /// Aus Rohbytes (Seed).
    #[must_use]
    pub fn from_bytes(bytes: [u8; ED25519_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Rohbytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; ED25519_KEY_LEN] {
        &self.0
    }

    /// Zugehöriger Verifikationsschlüssel.
    #[must_use]
    pub fn verifying(&self) -> VerifyingPublic {
        let sk = SigningKey::from_bytes(&self.0);
        VerifyingPublic(sk.verifying_key().to_bytes())
    }

    /// `Sig(sk, m)`.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; ED25519_SIG_LEN] {
        let sk = SigningKey::from_bytes(&self.0);
        sk.sign(message).to_bytes()
    }
}

impl VerifyingPublic {
    /// Aus Rohbytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; ED25519_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Rohbytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; ED25519_KEY_LEN] {
        &self.0
    }

    /// `Vrf(pk, m, σ)`.
    ///
    /// # Fehler
    ///
    /// [`CryptoError::SignatureInvalid`] bei ungültiger Signatur **und** bei
    /// ungültigem Schlüssel. Der Fehler unterscheidet die beiden Fälle
    /// bewusst nicht (`engineering-setup.md` §3.1: keine Rückschlüsse aus
    /// Fehlermeldungen).
    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8; ED25519_SIG_LEN],
    ) -> Result<(), CryptoError> {
        let vk = VerifyingKey::from_bytes(&self.0).map_err(|_| CryptoError::SignatureInvalid)?;
        // Schwache Schlüssel (Punkte kleiner Ordnung) abweisen: mit ihnen
        // liesse sich eine Signatur bauen, die für nahezu jede Nachricht
        // verifiziert. Die gesamte Schlüsselhierarchie aus §2 haengt daran,
        // dass `IK` genau eine Aussage bindet.
        if vk.is_weak() {
            return Err(CryptoError::SignatureInvalid);
        }
        let sig = Signature::from_bytes(signature);
        // `verify_strict` prueft zusaetzlich Torsionsanteile in `R`.
        vk.verify_strict(message, &sig)
            .map_err(|_| CryptoError::SignatureInvalid)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "Testcode"
)]
mod tests {
    use super::*;

    /// RFC 8032 §7.1 (Ed25519-Testvektoren) liegt lokal nicht vor: das Paket
    /// `ed25519-dalek-2.2.0` liefert nur einen Ed25519**ph**-Vektor aus §7.3
    /// mit, und die große `TESTVECTORS`-Datei ist nicht Teil des Pakets.
    #[test]
    #[ignore = "RFC 8032 §7.1 Testvektoren fehlen lokal — siehe TAGESBERICHT.md"]
    fn ed25519_rfc8032_vektoren() {
        panic!("Testvektoren bereitstellen, dann implementieren");
    }

    #[test]
    fn signatur_verifiziert() {
        let sk = SigningPrivate::from_bytes([42u8; 32]);
        let pk = sk.verifying();
        let sig = sk.sign(b"osk_ed_pub || id");
        assert!(pk.verify(b"osk_ed_pub || id", &sig).is_ok());
    }

    #[test]
    fn verfaelschte_nachricht_schlaegt_fehl() {
        let sk = SigningPrivate::from_bytes([42u8; 32]);
        let sig = sk.sign(b"original");
        assert_eq!(
            sk.verifying().verify(b"manipuliert", &sig),
            Err(CryptoError::SignatureInvalid)
        );
    }

    #[test]
    fn fremder_schluessel_schlaegt_fehl() {
        let sk = SigningPrivate::from_bytes([1u8; 32]);
        let fremd = SigningPrivate::from_bytes([2u8; 32]).verifying();
        let sig = sk.sign(b"m");
        assert_eq!(fremd.verify(b"m", &sig), Err(CryptoError::SignatureInvalid));
    }

    #[test]
    fn verfaelschte_signatur_schlaegt_fehl() {
        let sk = SigningPrivate::from_bytes([7u8; 32]);
        let mut sig = sk.sign(b"m");
        sig[0] ^= 0x01;
        assert_eq!(
            sk.verifying().verify(b"m", &sig),
            Err(CryptoError::SignatureInvalid)
        );
    }

    /// Regression zu Befund H-2 des Security-Reviews: Ein Punkt kleiner
    /// Ordnung als Verifikationsschluessel erlaubt Signaturen, die fuer
    /// nahezu jede Nachricht gelten. Die Bindung aus §2 („IK signiert alles
    /// Abgeleitete") haengt daran, dass das abgewiesen wird.
    #[test]
    fn schwacher_verifikationsschluessel_wird_abgewiesen() {
        // Der All-Zero-Punkt ist der bekannteste Vertreter kleiner Ordnung.
        let schwach = VerifyingPublic::from_bytes([0u8; 32]);
        assert_eq!(
            schwach.verify(b"beliebig", &[0u8; ED25519_SIG_LEN]),
            Err(CryptoError::SignatureInvalid)
        );
    }

    #[test]
    fn debug_gibt_kein_material_preis() {
        let sk = SigningPrivate::from_bytes([5u8; 32]);
        assert_eq!(format!("{sk:?}"), "SigningPrivate(redacted)");
        assert_eq!(format!("{:?}", sk.verifying()), "VerifyingPublic(redacted)");
    }
}
