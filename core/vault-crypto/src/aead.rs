//! AEAD: XChaCha20-Poly1305.
//!
//! Normativ: `spec/protokoll-spec.md` §1 („`AEAD(k, n, ad, pt)` —
//! XChaCha20-Poly1305"), §8 (`ciphertext = AEAD(mk, nonce, ad=H(dr_header),
//! pt=Payload)`), `spec/gesamtkonzept.md` §2.4 (Anhänge). ADR-05: Bibliothek
//! `chacha20poly1305`.
//!
//! Die 24-Byte-Nonce von XChaCha erlaubt zufällige oder abgeleitete Nonces
//! ohne praktisches Kollisionsrisiko. Im Double Ratchet wird sie aus dem
//! Message Key abgeleitet (siehe [`crate::ratchet`]), weil jeder Message Key
//! genau eine Nachricht schützt.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

use crate::error::CryptoError;

/// Länge des AEAD-Schlüssels in Bytes.
pub const AEAD_KEY_LEN: usize = 32;

/// Länge der XChaCha20-Nonce in Bytes.
pub const NONCE_LEN: usize = 24;

/// Länge des Poly1305-Tags in Bytes.
pub const TAG_LEN: usize = 16;

/// `AEAD(k, n, ad, pt)` — verschlüsselt und authentisiert.
///
/// Das Ergebnis ist `ciphertext ‖ tag`.
///
/// # Fehler
///
/// [`CryptoError::AeadSealFailed`], wenn die Bibliothek die Eingabe
/// zurückweist (in der Praxis nur bei absurd großen Puffern).
pub fn seal(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: ad,
            },
        )
        .map_err(|_| CryptoError::AeadSealFailed)
}

/// Gegenstück zu [`seal`].
///
/// # Fehler
///
/// [`CryptoError::AeadOpenFailed`] bei falschem Schlüssel, falscher Nonce,
/// abweichendem `ad` oder manipuliertem Chiffrat. Die Fälle werden bewusst
/// nicht unterschieden (`engineering-setup.md` §3.1).
pub fn open(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: ad,
            },
        )
        .map_err(|_| CryptoError::AeadOpenFailed)
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

    /// Offizielle Vektoren für XChaCha20-Poly1305 liegen lokal nur als
    /// Wycheproof-Binärblob (`.blb`) im Paket `chacha20poly1305-0.10.1` vor;
    /// zum Dekodieren fehlt das Crate `blobby`, das nicht aus dem Netz geholt
    /// werden durfte.
    #[test]
    #[ignore = "XChaCha20-Poly1305 Vektoren (RFC 8439 / Wycheproof) fehlen lokal — siehe TAGESBERICHT.md"]
    fn xchacha20poly1305_offizielle_vektoren() {
        panic!("Testvektoren bereitstellen, dann implementieren");
    }

    #[test]
    fn roundtrip() {
        let key = [1u8; AEAD_KEY_LEN];
        let nonce = [2u8; NONCE_LEN];
        let ct = seal(&key, &nonce, b"ad", b"geheime nachricht").unwrap();
        assert_ne!(ct.as_slice(), b"geheime nachricht");
        assert_eq!(ct.len(), b"geheime nachricht".len() + TAG_LEN);
        assert_eq!(
            open(&key, &nonce, b"ad", &ct).unwrap(),
            b"geheime nachricht"
        );
    }

    #[test]
    fn abweichendes_ad_schlaegt_fehl() {
        let key = [1u8; AEAD_KEY_LEN];
        let nonce = [2u8; NONCE_LEN];
        let ct = seal(&key, &nonce, b"ad-a", b"pt").unwrap();
        assert_eq!(
            open(&key, &nonce, b"ad-b", &ct),
            Err(CryptoError::AeadOpenFailed)
        );
    }

    #[test]
    fn manipuliertes_chiffrat_schlaegt_fehl() {
        let key = [1u8; AEAD_KEY_LEN];
        let nonce = [2u8; NONCE_LEN];
        let mut ct = seal(&key, &nonce, b"ad", b"pt").unwrap();
        ct[0] ^= 0x01;
        assert_eq!(
            open(&key, &nonce, b"ad", &ct),
            Err(CryptoError::AeadOpenFailed)
        );
    }

    #[test]
    fn falscher_schluessel_und_falsche_nonce_schlagen_fehl() {
        let ct = seal(&[1u8; AEAD_KEY_LEN], &[2u8; NONCE_LEN], b"", b"pt").unwrap();
        assert_eq!(
            open(&[9u8; AEAD_KEY_LEN], &[2u8; NONCE_LEN], b"", &ct),
            Err(CryptoError::AeadOpenFailed)
        );
        assert_eq!(
            open(&[1u8; AEAD_KEY_LEN], &[9u8; NONCE_LEN], b"", &ct),
            Err(CryptoError::AeadOpenFailed)
        );
    }

    #[test]
    fn leerer_klartext_ist_zulaessig() {
        let key = [3u8; AEAD_KEY_LEN];
        let nonce = [4u8; NONCE_LEN];
        let ct = seal(&key, &nonce, b"ad", b"").unwrap();
        assert_eq!(ct.len(), TAG_LEN);
        assert!(open(&key, &nonce, b"ad", &ct).unwrap().is_empty());
    }
}
