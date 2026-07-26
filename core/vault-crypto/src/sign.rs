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

    /// Kodierung des neutralen Elements der Ed25519-Gruppe: `y = 1`,
    /// Vorzeichenbit 0.
    fn neutrales_element() -> [u8; ED25519_KEY_LEN] {
        let mut b = [0u8; ED25519_KEY_LEN];
        b[0] = 1;
        b
    }

    /// Die **universelle Fälschung**: `A = R = neutrales Element`, `s = 0`.
    ///
    /// Die Verifikationsgleichung `[s]B = R + [k]A` wird damit zu
    /// `identity = identity + [k]·identity` — sie gilt für **jede**
    /// Nachricht, ohne dass der Fälscher irgendeinen Schlüssel kennt.
    fn universelle_faelschung() -> [u8; ED25519_SIG_LEN] {
        let mut sig = [0u8; ED25519_SIG_LEN];
        sig[0] = 1;
        sig
    }

    /// Regression zu Befund H-2 (erstes Review) und HOCH-1 (Gegenlesen).
    ///
    /// Der ursprüngliche Test prüfte gegen All-Zero-Schlüssel und
    /// All-Zero-Signatur — die werden auch **ohne** `verify_strict`
    /// abgewiesen, der Test blieb bei zurückgenommenem Fix grün und war
    /// damit wertlos. Dieser Test prüft gegen die tatsächliche universelle
    /// Fälschung: Ohne `verify_strict` verifiziert sie für jede Nachricht.
    ///
    /// Nachgewiesen per Scratchpad-Rücknahme: mit `verify` statt
    /// `verify_strict` wird dieser Test **rot**.
    #[test]
    fn universelle_faelschung_mit_neutralem_element_wird_abgewiesen() {
        let vk = VerifyingPublic::from_bytes(neutrales_element());
        let sig = universelle_faelschung();

        // Vier inhaltlich unvereinbare Nachrichten. Gegen den ungepatchten
        // Zustand verifiziert dieselbe Signatur für alle vier.
        for msg in [
            &b""[..],
            &b"beliebig"[..],
            &b"ueberweise 10 EUR"[..],
            &b"ueberweise 10000 EUR"[..],
        ] {
            assert_eq!(
                vk.verify(msg, &sig),
                Err(CryptoError::SignatureInvalid),
                "universelle Faelschung wurde akzeptiert"
            );
        }
    }

    /// Dieselbe Fälschung gegen **alle** Signaturpfade der Spec.
    ///
    /// `spec/protokoll-spec.md` kennt fünf Stellen, an denen eine Ed25519-
    /// Signatur die Identitätshierarchie trägt. Alle laufen über denselben
    /// Wrapper [`VerifyingPublic::verify`] — im ganzen Repo gibt es keinen
    /// zweiten Verifikationspfad, `ed25519_dalek` wird ausschließlich hier
    /// verwendet. Der Test hält beides fest: die Abweisung je Pfad und
    /// implizit, dass es nur einen Pfad gibt.
    #[test]
    fn universelle_faelschung_greift_an_keinem_signaturpfad() {
        let vk = VerifyingPublic::from_bytes(neutrales_element());
        let sig = universelle_faelschung();

        // Repraesentative Signatur-Eingaben je Pfad.
        let pfade: [(&str, &[u8]); 5] = [
            ("§3 cross_sig: Sig(IK, osk_ed_pub || id)", b"osk_ed_pub||0"),
            ("§2 IK ueber DEVK", b"devk_ed_pub||geraet-1"),
            ("§4 spk_sig: Sig(IK, spk_x_pub)", b"spk_x_pub"),
            ("§4 pqspk_sig: Sig(IK, pqspk_ek)", b"pqspk_ek"),
            ("§9.1 DeviceList.sig", b"device_list||epoch-7"),
        ];

        for (pfad, nachricht) in pfade {
            assert_eq!(
                vk.verify(nachricht, &sig),
                Err(CryptoError::SignatureInvalid),
                "Signaturpfad ungeschuetzt: {pfad}"
            );
        }
    }

    /// Ein schwacher Schlüssel darf auch dann nicht durchgehen, wenn die
    /// Signatur regulär geformt ist.
    #[test]
    fn schwacher_schluessel_mit_gueltig_geformter_signatur_wird_abgewiesen() {
        let echt = SigningPrivate::from_bytes([3u8; 32]);
        let regulaere_signatur = echt.sign(b"m");
        let schwach = VerifyingPublic::from_bytes(neutrales_element());
        assert_eq!(
            schwach.verify(b"m", &regulaere_signatur),
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
