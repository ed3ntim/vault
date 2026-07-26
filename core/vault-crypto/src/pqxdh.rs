//! PQXDH — X25519 + ML-KEM-768 hybrid (CR-1).
//!
//! Normativ: `spec/protokoll-spec.md` §5 (Kontakt-Handshake) und §2
//! (Schlüsselhierarchie), `spec/gesamtkonzept.md` §2.4; ADR-05
//! („PQXDH + Double Ratchet … Keine Eigenentwicklung erlaubt").
//!
//! §5 legt fest:
//!
//! ```text
//! EK_x  ← X25519 ephemeral
//! (K_pq, ct_pq) ← ML-KEM.Encaps(pqspk_ek)
//! DH1 = X25519(EK_x,  spk_x_pub)
//! DH2 = X25519(ik_x_B, spk_x_pub)
//! DH3 = X25519(EK_x,  ik_x_A_pub)
//! [DH4 = X25519(EK_x, opk) falls vorhanden]
//! SK = HKDF(DH1‖DH2‖DH3‖[DH4]‖K_pq)
//! ```
//!
//! # Was hier implementiert ist — und was nicht
//!
//! Der **klassische Anteil** ist vollständig: [`derive_sk`] berechnet `SK`
//! aus den vier DH-Werten und dem KEM-Geheimnis, [`initiator_dh_values`] und
//! [`responder_dh_values`] berechnen die DH-Werte spiegelbildlich.
//!
//! Der **KEM-Anteil fehlt**: `ML-KEM.Encaps` / `Decaps` sind nicht
//! implementiert, weil in dieser Umgebung keine ML-KEM-Bibliothek vorliegt
//! und nach den Vorgaben des Laufs keine nachgeladen werden durfte.
//! [`encapsulate`] und [`decapsulate`] geben deshalb
//! [`CryptoError::KemNotImplemented`] zurück.
//!
//! **TODO(ML-KEM):** Benötigt wird das Crate `ml-kem` (RustCrypto,
//! ML-KEM-768 nach FIPS 203). Reifegrad ist vor der Aufnahme gegen ADR-05
//! zu bewerten — die Crate ist noch vor 1.0. Bis dahin ist PQXDH **nicht**
//! einsatzfähig; die hybride Eigenschaft gegen „harvest now, decrypt later"
//! fehlt genau so lange. Kein Aufrufer darf `derive_sk` mit einem
//! konstanten oder leeren `k_pq` verwenden, um das zu umgehen.

use zeroize::Zeroize;

use crate::dh::{DhPrivate, DhPublic, X25519_LEN};
use crate::error::CryptoError;
use crate::kdf::{hkdf_sha256, RootKey, KEY_LEN};

/// Info-String der `SK`-Ableitung.
const INFO_SK: &[u8] = b"vault-pqxdh-sk";

/// Länge des ML-KEM-768-Shared-Secret in Bytes (FIPS 203).
pub const ML_KEM_SHARED_SECRET_LEN: usize = 32;

/// Die DH-Anteile von PQXDH nach §5.
///
/// `Debug` ist redigiert: die vier Werte sind zusammen mit `K_pq` das
/// gesamte Eingangsmaterial von `SK` (`engineering-setup.md` §3.1,
/// `CLAUDE.md` — keine Schlüssel in Logs).
#[derive(Clone)]
pub struct DhParts {
    /// `DH1 = X25519(EK_x, spk_x_pub)`
    pub dh1: [u8; X25519_LEN],
    /// `DH2 = X25519(ik_x_initiator, spk_x_pub)`
    pub dh2: [u8; X25519_LEN],
    /// `DH3 = X25519(EK_x, ik_x_responder_pub)`
    pub dh3: [u8; X25519_LEN],
    /// `DH4 = X25519(EK_x, opk)` — optional (§2: `OPK[]` ist optional).
    pub dh4: Option<[u8; X25519_LEN]>,
}

impl core::fmt::Debug for DhParts {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DhParts(redacted)")
    }
}

impl Drop for DhParts {
    fn drop(&mut self) {
        self.dh1.zeroize();
        self.dh2.zeroize();
        self.dh3.zeroize();
        // `as_mut` statt `take`: `take` verschiebt eine Kopie heraus und
        // loescht nur diese, waehrend die Originalbytes stehen bleiben.
        if let Some(d) = self.dh4.as_mut() {
            d.zeroize();
        }
    }
}

/// Berechnet die DH-Anteile auf der Seite des **Initiators** (§5: Bob).
///
/// # Fehler
///
/// [`CryptoError::InvalidKeyLength`], wenn eine DH-Operation kein
/// beitragendes Ergebnis liefert (Punkt kleiner Ordnung).
pub fn initiator_dh_values(
    ephemeral: &DhPrivate,
    identity: &DhPrivate,
    their_spk_pub: &DhPublic,
    their_identity_pub: &DhPublic,
    their_opk_pub: Option<&DhPublic>,
) -> Result<DhParts, CryptoError> {
    Ok(DhParts {
        dh1: ephemeral.diffie_hellman(their_spk_pub)?,
        dh2: identity.diffie_hellman(their_spk_pub)?,
        dh3: ephemeral.diffie_hellman(their_identity_pub)?,
        dh4: match their_opk_pub {
            Some(opk) => Some(ephemeral.diffie_hellman(opk)?),
            None => None,
        },
    })
}

/// Berechnet dieselben DH-Anteile auf der Seite des **Responders** (§5: Alice).
///
/// # Fehler
///
/// Wie [`initiator_dh_values`].
pub fn responder_dh_values(
    spk: &DhPrivate,
    identity: &DhPrivate,
    their_ephemeral_pub: &DhPublic,
    their_identity_pub: &DhPublic,
    opk: Option<&DhPrivate>,
) -> Result<DhParts, CryptoError> {
    Ok(DhParts {
        dh1: spk.diffie_hellman(their_ephemeral_pub)?,
        dh2: spk.diffie_hellman(their_identity_pub)?,
        dh3: identity.diffie_hellman(their_ephemeral_pub)?,
        dh4: match opk {
            Some(k) => Some(k.diffie_hellman(their_ephemeral_pub)?),
            None => None,
        },
    })
}

/// `SK = HKDF(DH1‖DH2‖DH3‖[DH4]‖K_pq)` nach §5.
///
/// Die Konkatenation ist eindeutig, weil alle DH-Werte 32 Bytes haben und
/// `k_pq` als letztes Element folgt; die Anwesenheit von `DH4` geht als
/// Domain-Trenner in `info` ein, damit „mit OPK" und „ohne OPK" nie dieselbe
/// Eingabe erzeugen können.
///
/// # Fehler
///
/// [`CryptoError::InvalidKeyLength`] aus der HKDF-Expansion.
pub fn derive_sk(parts: &DhParts, k_pq: &[u8]) -> Result<RootKey, CryptoError> {
    // Feste Laenge erzwingen. Zwei Gruende: (1) ohne Laengenpruefung waere
    // ein leeres `k_pq` der bequemste Weg, PQXDH ohne PQ-Anteil „zum Laufen
    // zu bringen" — genau die von CLAUDE.md verbotene Platzhalter-Krypto;
    // (2) bei fester Laenge ist die Konkatenation eindeutig, ohne das
    // Laengenpraefix aus §1 zu brauchen.
    if k_pq.len() != ML_KEM_SHARED_SECRET_LEN {
        return Err(CryptoError::InvalidKeyLength);
    }
    let mut ikm = Vec::with_capacity(X25519_LEN.saturating_mul(4).saturating_add(k_pq.len()));
    ikm.extend_from_slice(&parts.dh1);
    ikm.extend_from_slice(&parts.dh2);
    ikm.extend_from_slice(&parts.dh3);
    let info: &[u8] = match parts.dh4 {
        Some(ref d) => {
            ikm.extend_from_slice(d);
            b"vault-pqxdh-sk-opk"
        }
        None => INFO_SK,
    };
    ikm.extend_from_slice(k_pq);

    let mut okm = [0u8; KEY_LEN];
    let result = hkdf_sha256(None, &ikm, info, &mut okm);
    ikm.zeroize();
    result?;

    let sk = RootKey::from_bytes(okm);
    okm.zeroize();
    Ok(sk)
}

/// `ML-KEM.Encaps(pqspk_ek)` — **nicht implementiert**.
///
/// # Fehler
///
/// Immer [`CryptoError::KemNotImplemented`]. Siehe Modul-Dokumentation:
/// Es fehlt das Crate `ml-kem`.
pub fn encapsulate(_encapsulation_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    Err(CryptoError::KemNotImplemented)
}

/// `ML-KEM.Decaps(ct_pq)` — **nicht implementiert**.
///
/// # Fehler
///
/// Immer [`CryptoError::KemNotImplemented`]. Siehe Modul-Dokumentation.
pub fn decapsulate(_decapsulation_key: &[u8], _ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Err(CryptoError::KemNotImplemented)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "Testcode"
)]
mod tests {
    use super::*;

    fn sk(n: u8) -> DhPrivate {
        DhPrivate::from_bytes([n; 32])
    }

    #[test]
    fn beide_seiten_leiten_dasselbe_sk_ab() {
        let ek = sk(1);
        let ik_i = sk(2);
        let spk_r = sk(3);
        let ik_r = sk(4);

        let i = initiator_dh_values(&ek, &ik_i, &spk_r.public(), &ik_r.public(), None).unwrap();
        let r = responder_dh_values(&spk_r, &ik_r, &ek.public(), &ik_i.public(), None).unwrap();

        assert_eq!(i.dh1, r.dh1);
        assert_eq!(i.dh2, r.dh2);
        assert_eq!(i.dh3, r.dh3);

        let k_pq = &[1u8; ML_KEM_SHARED_SECRET_LEN];
        let sk_i = derive_sk(&i, k_pq).unwrap();
        let sk_r = derive_sk(&r, k_pq).unwrap();
        assert_eq!(sk_i.as_bytes(), sk_r.as_bytes());
    }

    #[test]
    fn beide_seiten_leiten_dasselbe_sk_mit_opk_ab() {
        let ek = sk(1);
        let ik_i = sk(2);
        let spk_r = sk(3);
        let ik_r = sk(4);
        let opk_r = sk(5);

        let i = initiator_dh_values(
            &ek,
            &ik_i,
            &spk_r.public(),
            &ik_r.public(),
            Some(&opk_r.public()),
        )
        .unwrap();
        let r =
            responder_dh_values(&spk_r, &ik_r, &ek.public(), &ik_i.public(), Some(&opk_r)).unwrap();

        assert_eq!(i.dh4, r.dh4);
        let k_pq = &[2u8; ML_KEM_SHARED_SECRET_LEN];
        assert_eq!(
            derive_sk(&i, k_pq).unwrap().as_bytes(),
            derive_sk(&r, k_pq).unwrap().as_bytes()
        );
    }

    #[test]
    fn mit_und_ohne_opk_ergeben_verschiedene_sk() {
        let ek = sk(1);
        let ik_i = sk(2);
        let spk_r = sk(3);
        let ik_r = sk(4);
        let opk_r = sk(5);

        let ohne = initiator_dh_values(&ek, &ik_i, &spk_r.public(), &ik_r.public(), None).unwrap();
        let mit = initiator_dh_values(
            &ek,
            &ik_i,
            &spk_r.public(),
            &ik_r.public(),
            Some(&opk_r.public()),
        )
        .unwrap();

        assert_ne!(
            derive_sk(&ohne, &[3u8; ML_KEM_SHARED_SECRET_LEN])
                .unwrap()
                .as_bytes(),
            derive_sk(&mit, &[3u8; ML_KEM_SHARED_SECRET_LEN])
                .unwrap()
                .as_bytes()
        );
    }

    #[test]
    fn abweichendes_kem_geheimnis_aendert_sk() {
        let ek = sk(1);
        let ik_i = sk(2);
        let spk_r = sk(3);
        let ik_r = sk(4);
        let parts = initiator_dh_values(&ek, &ik_i, &spk_r.public(), &ik_r.public(), None).unwrap();

        assert_ne!(
            derive_sk(&parts, &[4u8; ML_KEM_SHARED_SECRET_LEN])
                .unwrap()
                .as_bytes(),
            derive_sk(&parts, &[5u8; ML_KEM_SHARED_SECRET_LEN])
                .unwrap()
                .as_bytes()
        );
    }

    /// Regression zu Befund M-3: ein leeres oder zu kurzes `k_pq` darf nicht
    /// klaglos ein rein klassisches `SK` liefern — das waere PQXDH ohne
    /// PQ-Anteil, ohne dass es jemand merkt.
    #[test]
    fn falsche_laenge_von_k_pq_wird_abgewiesen() {
        let ek = sk(1);
        let ik_i = sk(2);
        let spk_r = sk(3);
        let ik_r = sk(4);
        let parts = initiator_dh_values(&ek, &ik_i, &spk_r.public(), &ik_r.public(), None).unwrap();

        assert_eq!(
            derive_sk(&parts, b"").err(),
            Some(CryptoError::InvalidKeyLength)
        );
        assert_eq!(
            derive_sk(&parts, &[0u8; 31]).err(),
            Some(CryptoError::InvalidKeyLength)
        );
        assert!(derive_sk(&parts, &[0u8; ML_KEM_SHARED_SECRET_LEN]).is_ok());
    }

    #[test]
    fn debug_gibt_kein_material_preis() {
        let ek = sk(1);
        let parts =
            initiator_dh_values(&ek, &sk(2), &sk(3).public(), &sk(4).public(), None).unwrap();
        assert_eq!(format!("{parts:?}"), "DhParts(redacted)");
    }

    #[test]
    fn kem_ist_noch_nicht_implementiert() {
        assert_eq!(encapsulate(b"ek"), Err(CryptoError::KemNotImplemented));
        assert_eq!(
            decapsulate(b"dk", b"ct"),
            Err(CryptoError::KemNotImplemented)
        );
    }
}
