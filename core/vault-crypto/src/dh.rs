//! X25519 — Diffie-Hellman-Schlüsselaustausch.
//!
//! Normativ: `spec/protokoll-spec.md` §1 („`X25519` — ECDH-Schlüsselaustausch"),
//! §2 (Schlüsselhierarchie: `IK_x`, `SPK`, `OPK[]`, `CA_{c,X}`), §5 (PQXDH),
//! §8 (DH-Ratchet). ADR-05: Bibliothek `x25519-dalek`.
//!
//! Dieses Modul erzeugt **keine** Schlüssel aus Zufall — die Erzeugung
//! unterliegt dem Entropie-Gate (`spec/gesamtkonzept.md` §2.1, ID-2) und
//! gehört nach `vault-identity`. Hier gibt es nur Ableitung aus vorhandenen
//! Bytes und die DH-Operation selbst; damit bleibt `vault-crypto` frei von
//! I/O (Schichtregel, Gate G-5).

use subtle::{Choice, ConstantTimeEq};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

/// Länge eines X25519-Schlüssels in Bytes.
pub const X25519_LEN: usize = 32;

/// Privater X25519-Schlüssel.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DhPrivate([u8; X25519_LEN]);

/// Öffentlicher X25519-Schlüssel.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DhPublic([u8; X25519_LEN]);

impl core::fmt::Debug for DhPrivate {
    /// Kein Schlüsselmaterial in der Ausgabe (`engineering-setup.md` §3.1).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DhPrivate(redacted)")
    }
}

impl core::fmt::Debug for DhPublic {
    /// Auch öffentliche Schlüssel sind Identifikatoren und gehören nicht in
    /// Logs (`CLAUDE.md`: keine Kontakt-IDs in Logs).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DhPublic(redacted)")
    }
}

impl DhPrivate {
    /// Aus Rohbytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; X25519_LEN]) -> Self {
        Self(bytes)
    }

    /// Rohbytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; X25519_LEN] {
        &self.0
    }

    /// Zugehöriger öffentlicher Schlüssel.
    #[must_use]
    pub fn public(&self) -> DhPublic {
        let secret = StaticSecret::from(self.0);
        DhPublic(PublicKey::from(&secret).to_bytes())
    }

    /// X25519-DH mit einem fremden öffentlichen Schlüssel.
    ///
    /// # Fehler
    ///
    /// [`CryptoError::InvalidKeyLength`], wenn das Ergebnis der
    /// Contributory-Behaviour-Prüfung nicht standhält (All-Zero-Output, d. h.
    /// der Gegenpart hat einen Punkt kleiner Ordnung geschickt).
    pub fn diffie_hellman(&self, their: &DhPublic) -> Result<[u8; X25519_LEN], CryptoError> {
        let secret = StaticSecret::from(self.0);
        let shared = secret.diffie_hellman(&PublicKey::from(their.0));
        if shared.was_contributory() {
            Ok(shared.to_bytes())
        } else {
            Err(CryptoError::InvalidKeyLength)
        }
    }
}

impl DhPublic {
    /// Aus Rohbytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; X25519_LEN]) -> Self {
        Self(bytes)
    }

    /// Rohbytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; X25519_LEN] {
        &self.0
    }
}

impl ConstantTimeEq for DhPrivate {
    /// Konstantzeitiger Vergleich (`spec/engineering-setup.md` §3.1).
    /// `DhPrivate` implementiert bewusst kein `PartialEq`.
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "Testcode")]
mod tests {
    use super::*;

    /// RFC 7748 §5.2, erster Vektor der X25519-Funktion.
    ///
    /// Quelle: die Vektoren liegen lokal im Paket `x25519-dalek-2.0.1`
    /// (`tests/x25519_tests.rs`, `rfc7748_ladder_test1_vectorset1`) vor und
    /// stammen dort aus RFC 7748. Nicht selbst erdacht.
    #[test]
    fn x25519_rfc7748_vektor_1() {
        let input_scalar: [u8; 32] = [
            0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46,
            0x5e, 0xdd, 0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44,
            0xba, 0x44, 0x9a, 0xc4,
        ];
        let input_point: [u8; 32] = [
            0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1,
            0x5f, 0x7c, 0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b, 0x10, 0xa9, 0x03, 0xa6,
            0xd0, 0xab, 0x1c, 0x4c,
        ];
        let expected: [u8; 32] = [
            0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90, 0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d,
            0x08, 0x4f, 0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7, 0x54, 0xb4, 0x07, 0x55,
            0x77, 0xa2, 0x85, 0x52,
        ];

        let sk = DhPrivate::from_bytes(input_scalar);
        let pk = DhPublic::from_bytes(input_point);
        assert_eq!(sk.diffie_hellman(&pk).unwrap(), expected);
    }

    #[test]
    fn beide_seiten_erhalten_dasselbe_geheimnis() {
        let a = DhPrivate::from_bytes([1u8; 32]);
        let b = DhPrivate::from_bytes([2u8; 32]);
        let ab = a.diffie_hellman(&b.public()).unwrap();
        let ba = b.diffie_hellman(&a.public()).unwrap();
        assert_eq!(ab, ba);
    }

    #[test]
    fn punkt_kleiner_ordnung_wird_abgewiesen() {
        // All-Zero ist ein Punkt kleiner Ordnung; das DH-Ergebnis wäre
        // beitragsfrei und darf nicht verwendet werden.
        let a = DhPrivate::from_bytes([3u8; 32]);
        let low_order = DhPublic::from_bytes([0u8; 32]);
        assert_eq!(
            a.diffie_hellman(&low_order),
            Err(CryptoError::InvalidKeyLength)
        );
    }

    #[test]
    fn debug_gibt_kein_material_preis() {
        let sk = DhPrivate::from_bytes([9u8; 32]);
        assert_eq!(format!("{sk:?}"), "DhPrivate(redacted)");
        assert_eq!(format!("{:?}", sk.public()), "DhPublic(redacted)");
    }
}
