//! HKDF-SHA-256 sowie `KDF_RK` / `KDF_CK` des Double Ratchet.
//!
//! Normativ: `spec/protokoll-spec.md` §1 („`HKDF` — HKDF-SHA-256
//! (Extract-and-Expand)", „`KDF_RK`, `KDF_CK` — Double-Ratchet-Root/Chain-KDF")
//! und §8 („Double Ratchet wie Signal-Spezifikation"). ADR-05: keine
//! Eigenentwicklung — HKDF aus `hkdf`/`sha2`, HMAC aus `hmac`.
//!
//! Die Konstanten von `KDF_CK` (0x01 für den Message Key, 0x02 für den
//! nächsten Chain Key) stammen aus der Signal-Double-Ratchet-Spezifikation,
//! nicht aus eigener Festlegung.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

/// Länge aller symmetrischen Schlüssel dieses Moduls in Bytes.
pub const KEY_LEN: usize = 32;

/// Info-String der Root-Key-Ableitung.
const INFO_ROOT: &[u8] = b"vault-dr-root";

/// Root Key des Double Ratchet.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RootKey([u8; KEY_LEN]);

/// Chain Key einer Sende- oder Empfangskette.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ChainKey([u8; KEY_LEN]);

/// Message Key für genau eine Nachricht.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MessageKey([u8; KEY_LEN]);

macro_rules! key_type_impl {
    ($t:ty, $name:literal) => {
        impl $t {
            /// Aus Rohbytes.
            #[must_use]
            pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
                Self(bytes)
            }

            /// Zugriff auf die Rohbytes.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
                &self.0
            }
        }

        impl core::fmt::Debug for $t {
            /// Gibt **kein** Schlüsselmaterial preis
            /// (`spec/engineering-setup.md` §3.1).
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!($name, "(redacted)"))
            }
        }
    };
}

key_type_impl!(RootKey, "RootKey");
key_type_impl!(ChainKey, "ChainKey");
key_type_impl!(MessageKey, "MessageKey");

/// HKDF-SHA-256 (Extract-and-Expand) nach RFC 5869.
///
/// # Fehler
///
/// [`CryptoError::InvalidKeyLength`], wenn `okm` länger ist, als HKDF
/// liefern kann (255 · 32 Bytes).
pub fn hkdf_sha256(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[u8],
    okm: &mut [u8],
) -> Result<(), CryptoError> {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    hk.expand(info, okm)
        .map_err(|_| CryptoError::InvalidKeyLength)
}

/// `KDF_RK` — Root-Key-Ableitung des DH-Ratchet-Schritts.
///
/// Signal-Double-Ratchet: `(RK', CK) = HKDF(salt = RK, ikm = dh_out)`.
///
/// # Fehler
///
/// [`CryptoError::InvalidKeyLength`] aus der HKDF-Expansion.
pub fn kdf_rk(rk: &RootKey, dh_out: &[u8; KEY_LEN]) -> Result<(RootKey, ChainKey), CryptoError> {
    let mut okm = [0u8; 64];
    hkdf_sha256(Some(rk.as_bytes()), dh_out, INFO_ROOT, &mut okm)?;

    let mut next_rk = [0u8; KEY_LEN];
    let mut next_ck = [0u8; KEY_LEN];
    let (a, b) = okm.split_at(KEY_LEN);
    next_rk.copy_from_slice(a);
    next_ck.copy_from_slice(b);
    okm.zeroize();

    Ok((RootKey(next_rk), ChainKey(next_ck)))
}

/// `KDF_CK` — symmetrischer Ratchet-Schritt einer Kette.
///
/// Signal-Double-Ratchet: `MK = HMAC(CK, 0x01)`, `CK' = HMAC(CK, 0x02)`.
///
/// # Fehler
///
/// [`CryptoError::InvalidKeyLength`], wenn HMAC den Schlüssel nicht annimmt.
pub fn kdf_ck(ck: &ChainKey) -> Result<(ChainKey, MessageKey), CryptoError> {
    let mk = hmac_step(ck, 0x01)?;
    let next = hmac_step(ck, 0x02)?;
    Ok((ChainKey(next), MessageKey(mk)))
}

fn hmac_step(ck: &ChainKey, byte: u8) -> Result<[u8; KEY_LEN], CryptoError> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(ck.as_bytes()).map_err(|_| CryptoError::InvalidKeyLength)?;
    mac.update(&[byte]);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; KEY_LEN];
    let slice: &[u8] = tag.as_slice();
    let head = slice.get(..KEY_LEN).ok_or(CryptoError::InvalidKeyLength)?;
    out.copy_from_slice(head);
    Ok(out)
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

    /// RFC 5869 Appendix A: die offiziellen Vektoren liegen in dieser
    /// Umgebung nicht vor und durften nach den Vorgaben des Laufs nicht aus
    /// dem Netz geholt werden. Der Test bleibt ignoriert, statt gegen selbst
    /// erdachte Werte zu prüfen.
    #[test]
    #[ignore = "RFC 5869 A.1-A.3 Testvektoren fehlen lokal — siehe TAGESBERICHT.md"]
    fn hkdf_rfc5869_vektoren() {
        panic!("Testvektoren bereitstellen, dann implementieren");
    }

    #[test]
    fn hkdf_ist_deterministisch_und_infoabhaengig() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        hkdf_sha256(Some(b"salt"), b"ikm", b"info", &mut a).unwrap();
        hkdf_sha256(Some(b"salt"), b"ikm", b"info", &mut b).unwrap();
        assert_eq!(a, b, "gleiche Eingabe muss gleiche Ausgabe liefern");

        let mut c = [0u8; 32];
        hkdf_sha256(Some(b"salt"), b"ikm", b"anderes-info", &mut c).unwrap();
        assert_ne!(a, c, "anderes info muss anderes OKM liefern");
    }

    #[test]
    fn hkdf_lehnt_uebergrosse_ausgabe_ab() {
        let mut zu_gross = vec![0u8; 255 * 32 + 1];
        assert_eq!(
            hkdf_sha256(None, b"ikm", b"info", &mut zu_gross),
            Err(CryptoError::InvalidKeyLength)
        );
    }

    #[test]
    fn kdf_rk_trennt_root_und_chain() {
        let rk = RootKey::from_bytes([7u8; 32]);
        let (rk2, ck) = kdf_rk(&rk, &[9u8; 32]).unwrap();
        assert_ne!(rk2.as_bytes(), rk.as_bytes(), "Root Key muss sich ändern");
        assert_ne!(
            rk2.as_bytes(),
            ck.as_bytes(),
            "RK und CK müssen verschieden sein"
        );

        let (rk3, ck3) = kdf_rk(&rk, &[9u8; 32]).unwrap();
        assert_eq!(rk2.as_bytes(), rk3.as_bytes(), "deterministisch");
        assert_eq!(ck.as_bytes(), ck3.as_bytes(), "deterministisch");
    }

    #[test]
    fn kdf_ck_schreitet_fort_und_trennt_mk() {
        let ck = ChainKey::from_bytes([1u8; 32]);
        let (ck2, mk) = kdf_ck(&ck).unwrap();
        assert_ne!(ck2.as_bytes(), ck.as_bytes());
        assert_ne!(ck2.as_bytes(), mk.as_bytes());

        let (ck3, mk2) = kdf_ck(&ck2).unwrap();
        assert_ne!(ck3.as_bytes(), ck2.as_bytes());
        assert_ne!(mk2.as_bytes(), mk.as_bytes(), "je Kettenschritt neuer MK");
    }

    #[test]
    fn debug_gibt_kein_schluesselmaterial_preis() {
        let k = MessageKey::from_bytes([0xABu8; 32]);
        let s = format!("{k:?}");
        assert_eq!(s, "MessageKey(redacted)");
    }
}
