//! `Invitation` — Kontaktaufbau out-of-band (CT-1).
//!
//! Normativ: `spec/protokoll-spec.md` §4. Einmalig, kurzlebig, replay-fest;
//! Größe ~400–600 B, damit sie als QR-Code der Version ≤ 20 darstellbar
//! bleibt (Spike S6).
//!
//! # Feldnummerierung — Implementierungsfestlegung, nicht Spec
//!
//! §4 gibt die Feld*namen* vor, nicht ihre CBOR-Kodierung. Hier werden Maps
//! mit `u64`-Schlüsseln in der unten festgelegten Reihenfolge verwendet, weil
//! das kompakt ist und die kanonische Sortierung trivial erfüllt. **GATE-6**
//! („Wire-Format final (CBOR-Profil)") ist offen und kann das ändern — die
//! Nummerierung ist deshalb an einer Stelle gebündelt und zur Bestätigung
//! vorgelegt (siehe `TAGESBERICHT.md`).

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::codec::{Decoder, Encoder};
use crate::error::WireError;

/// Unterstützte Fassung nach §4 (`v: u8 = 1`).
pub const VERSION: u64 = 1;

/// Länge von `invite_nonce` in Bytes (§4: 16 B).
pub const INVITE_NONCE_LEN: usize = 16;

/// Kompartiment-Anteil einer Invitation (§4).
///
/// Enthält mit `ca_priv` einen **privaten** Schlüssel und mit `onion_addr`
/// eine Onion-Adresse. Deshalb `ZeroizeOnDrop` und ein redigiertes `Debug`
/// (`CLAUDE.md`, `spec/engineering-setup.md` §3.1) — dasselbe Muster wie bei
/// den Schlüsseltypen in `vault-crypto`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CompartmentPart {
    /// Onion-Adresse des Kompartiments.
    pub onion_addr: String,
    /// Öffentlicher Onion-Service-Key `osk_ed_pub`.
    pub osk_ed_pub: [u8; 32],
    /// `cross_sig = Sig(IK, osk_ed_pub ‖ id)`.
    pub cross_sig: [u8; 64],
    /// Client-Auth-Privatschlüssel für den Eingeladenen.
    pub ca_priv: [u8; 32],
}

/// Prekey-Buendel einer Invitation (§4).
///
/// Redigiertes `Debug`: oeffentliche Schluessel sind Identifikatoren
/// (`CLAUDE.md`).
#[derive(Clone, PartialEq, Eq)]
pub struct PrekeyBundle {
    /// Signierter X25519-Prekey.
    pub spk_x_pub: [u8; 32],
    /// `Sig(IK, spk_x_pub)`.
    pub spk_sig: [u8; 64],
    /// ML-KEM-Encapsulation-Key.
    pub pqspk_ek: Vec<u8>,
    /// `Sig(IK, pqspk_ek)`.
    pub pqspk_sig: [u8; 64],
    /// Optionaler einmaliger X25519-Prekey.
    pub opk_x_pub: Option<[u8; 32]>,
    /// Optionaler einmaliger ML-KEM-Encapsulation-Key.
    pub pqopk_ek: Option<Vec<u8>>,
}

/// Invitation nach §4.
///
/// Redigiertes `Debug`: enthaelt Identitaetsschluessel, eine Onion-Adresse
/// und einen privaten Client-Auth-Schluessel.
#[derive(Clone, PartialEq, Eq)]
pub struct Invitation {
    /// Identitätsschlüssel des Einladenden (Ed25519).
    pub inviter_ik_ed_pub: [u8; 32],
    /// Identitätsschlüssel des Einladenden (X25519).
    pub inviter_ik_x_pub: [u8; 32],
    /// Kompartiment-Anteil.
    pub compartment: CompartmentPart,
    /// Prekey-Bündel.
    pub prekey_bundle: PrekeyBundle,
    /// Einmal-Nonce gegen Replay (§4).
    pub invite_nonce: [u8; INVITE_NONCE_LEN],
    /// Ablaufzeitpunkt, Unix-Sekunden (§1).
    pub expires_at: u64,
    /// `Sig(IK, H(alle vorstehenden Felder))`.
    pub sig: [u8; 64],
}

impl Invitation {
    /// Kodiert deterministisch nach CBOR.
    ///
    /// # Fehler
    ///
    /// Fehler aus [`Encoder::finish`]; ein Fehler hier wäre ein Fehler dieser
    /// Serialisierung selbst.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut e = Encoder::new();
        e.map(6);

        e.u64(0);
        e.u64(VERSION);

        e.u64(1);
        e.bytes(&self.inviter_ik_ed_pub);

        e.u64(2);
        e.bytes(&self.inviter_ik_x_pub);

        e.u64(3);
        e.map(4);
        e.u64(0);
        e.text(&self.compartment.onion_addr);
        e.u64(1);
        e.bytes(&self.compartment.osk_ed_pub);
        e.u64(2);
        e.bytes(&self.compartment.cross_sig);
        e.u64(3);
        e.bytes(&self.compartment.ca_priv);

        e.u64(4);
        e.map(6);
        e.u64(0);
        e.bytes(&self.prekey_bundle.spk_x_pub);
        e.u64(1);
        e.bytes(&self.prekey_bundle.spk_sig);
        e.u64(2);
        e.bytes(&self.prekey_bundle.pqspk_ek);
        e.u64(3);
        e.bytes(&self.prekey_bundle.pqspk_sig);
        e.u64(4);
        match self.prekey_bundle.opk_x_pub {
            Some(ref k) => e.bytes(k),
            None => e.null(),
        }
        e.u64(5);
        match self.prekey_bundle.pqopk_ek {
            Some(ref k) => e.bytes(k),
            None => e.null(),
        }

        e.u64(5);
        e.map(3);
        e.u64(0);
        e.bytes(&self.invite_nonce);
        e.u64(1);
        e.u64(self.expires_at);
        e.u64(2);
        e.bytes(&self.sig);

        e.finish()
    }

    /// Liest eine Invitation.
    ///
    /// Die Eingabe muss deterministisch kodiert sein; [`Decoder::new`] weist
    /// alles andere ab.
    ///
    /// # Fehler
    ///
    /// * [`WireError::UnsupportedVersion`] — `v` ist nicht [`VERSION`].
    /// * [`WireError::FieldMismatch`] — Feldzahl oder Schlüssel passen nicht.
    /// * weitere Fehler aus [`crate::codec`].
    pub fn decode(input: &[u8]) -> Result<Self, WireError> {
        let mut d = Decoder::new(input)?;
        expect_map(&mut d, 6)?;

        expect_key(&mut d, 0)?;
        if d.u64()? != VERSION {
            return Err(WireError::UnsupportedVersion);
        }

        expect_key(&mut d, 1)?;
        let inviter_ik_ed_pub = d.byte_array::<32>()?;
        expect_key(&mut d, 2)?;
        let inviter_ik_x_pub = d.byte_array::<32>()?;

        expect_key(&mut d, 3)?;
        expect_map(&mut d, 4)?;
        expect_key(&mut d, 0)?;
        let onion_addr = d.text()?.to_owned();
        expect_key(&mut d, 1)?;
        let osk_ed_pub = d.byte_array::<32>()?;
        expect_key(&mut d, 2)?;
        let cross_sig = d.byte_array::<64>()?;
        expect_key(&mut d, 3)?;
        let ca_priv = d.byte_array::<32>()?;

        expect_key(&mut d, 4)?;
        expect_map(&mut d, 6)?;
        expect_key(&mut d, 0)?;
        let spk_x_pub = d.byte_array::<32>()?;
        expect_key(&mut d, 1)?;
        let spk_sig = d.byte_array::<64>()?;
        expect_key(&mut d, 2)?;
        let pqspk_ek = d.bytes()?.to_vec();
        expect_key(&mut d, 3)?;
        let pqspk_sig = d.byte_array::<64>()?;
        expect_key(&mut d, 4)?;
        let opk_x_pub = d.optional_byte_array::<32>()?;
        expect_key(&mut d, 5)?;
        let pqopk_ek = d.optional_bytes()?.map(<[u8]>::to_vec);

        expect_key(&mut d, 5)?;
        expect_map(&mut d, 3)?;
        expect_key(&mut d, 0)?;
        let invite_nonce = d.byte_array::<INVITE_NONCE_LEN>()?;
        expect_key(&mut d, 1)?;
        let expires_at = d.u64()?;
        expect_key(&mut d, 2)?;
        let sig = d.byte_array::<64>()?;

        d.finish()?;

        Ok(Self {
            inviter_ik_ed_pub,
            inviter_ik_x_pub,
            compartment: CompartmentPart {
                onion_addr,
                osk_ed_pub,
                cross_sig,
                ca_priv,
            },
            prekey_bundle: PrekeyBundle {
                spk_x_pub,
                spk_sig,
                pqspk_ek,
                pqspk_sig,
                opk_x_pub,
                pqopk_ek,
            },
            invite_nonce,
            expires_at,
            sig,
        })
    }
}

fn expect_map(d: &mut Decoder<'_>, len: usize) -> Result<(), WireError> {
    if d.map_len()? == len {
        Ok(())
    } else {
        Err(WireError::FieldMismatch)
    }
}

fn expect_key(d: &mut Decoder<'_>, key: u64) -> Result<(), WireError> {
    if d.u64()? == key {
        Ok(())
    } else {
        Err(WireError::FieldMismatch)
    }
}

impl core::fmt::Debug for CompartmentPart {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CompartmentPart(redacted)")
    }
}

impl core::fmt::Debug for PrekeyBundle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PrekeyBundle(redacted)")
    }
}

impl core::fmt::Debug for Invitation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Invitation(redacted)")
    }
}

impl PartialEq for CompartmentPart {
    /// `ca_priv` ist nach §4 ein **privater** Schlüssel und wird deshalb
    /// konstantzeitig verglichen (`spec/engineering-setup.md` §3.1). Ein
    /// abgeleitetes `PartialEq` bräche früh ab und wäre ein Zeitorakel.
    fn eq(&self, other: &Self) -> bool {
        self.onion_addr == other.onion_addr
            && self.osk_ed_pub == other.osk_ed_pub
            && self.cross_sig == other.cross_sig
            && bool::from(self.ca_priv.ct_eq(&other.ca_priv))
    }
}

impl Eq for CompartmentPart {}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "Testcode"
)]
mod tests {
    use super::*;

    fn beispiel() -> Invitation {
        Invitation {
            inviter_ik_ed_pub: [1u8; 32],
            inviter_ik_x_pub: [2u8; 32],
            compartment: CompartmentPart {
                onion_addr: "a".repeat(56),
                osk_ed_pub: [3u8; 32],
                cross_sig: [4u8; 64],
                ca_priv: [5u8; 32],
            },
            prekey_bundle: PrekeyBundle {
                spk_x_pub: [6u8; 32],
                spk_sig: [7u8; 64],
                pqspk_ek: vec![8u8; 1184],
                pqspk_sig: [9u8; 64],
                opk_x_pub: None,
                pqopk_ek: None,
            },
            invite_nonce: [10u8; INVITE_NONCE_LEN],
            expires_at: 1_800_000_000,
            sig: [11u8; 64],
        }
    }

    #[test]
    fn roundtrip() {
        let inv = beispiel();
        let bytes = inv.encode().unwrap();
        assert_eq!(Invitation::decode(&bytes).unwrap(), inv);
    }

    #[test]
    fn roundtrip_mit_optionalen_prekeys() {
        let mut inv = beispiel();
        inv.prekey_bundle.opk_x_pub = Some([12u8; 32]);
        inv.prekey_bundle.pqopk_ek = Some(vec![13u8; 1184]);
        let bytes = inv.encode().unwrap();
        assert_eq!(Invitation::decode(&bytes).unwrap(), inv);
    }

    #[test]
    fn kodierung_ist_deterministisch() {
        let inv = beispiel();
        let erste = inv.encode().unwrap();
        for _ in 0..50 {
            assert_eq!(inv.encode().unwrap(), erste);
        }
    }

    #[test]
    fn falsche_version_wird_abgewiesen() {
        let inv = beispiel();
        let mut bytes = inv.encode().unwrap();
        // Erstes Feld ist Schluessel 0 mit Wert VERSION; Wert liegt an Index 2.
        bytes[2] = 0x02;
        assert_eq!(
            Invitation::decode(&bytes),
            Err(WireError::UnsupportedVersion)
        );
    }

    #[test]
    fn nicht_kanonische_eingabe_wird_abgewiesen() {
        assert_eq!(
            Invitation::decode(&[0x18, 0x17]),
            Err(WireError::NonMinimalHead)
        );
    }

    #[test]
    fn abgeschnittene_eingabe_wird_abgewiesen() {
        let bytes = beispiel().encode().unwrap();
        let kurz = &bytes[..bytes.len() / 2];
        assert!(Invitation::decode(kurz).is_err());
    }

    #[test]
    fn groesse_bleibt_im_qr_rahmen() {
        // §4: "vollstaendige Invitation ~400-600 B" ohne PQ-Anteil; mit
        // ML-KEM-768-Prekey (1184 B) liegt sie darueber — genau die Frage,
        // die Spike S6 klaert. Der Test dokumentiert die tatsaechliche Groesse.
        let mit_pq = beispiel().encode().unwrap().len();
        let mut ohne_pq = beispiel();
        ohne_pq.prekey_bundle.pqspk_ek = Vec::new();
        let ohne_pq = ohne_pq.encode().unwrap().len();
        assert!(
            ohne_pq < 600,
            "klassischer Anteil sollte unter 600 B bleiben: {ohne_pq}"
        );
        assert!(mit_pq > ohne_pq);
    }
}

#[cfg(test)]
mod debug_tests {
    use super::*;

    #[test]
    fn debug_gibt_kein_schluesselmaterial_und_keine_onion_adresse_preis() {
        let inv = Invitation {
            inviter_ik_ed_pub: [1u8; 32],
            inviter_ik_x_pub: [2u8; 32],
            compartment: CompartmentPart {
                onion_addr: "geheimeadresse".to_owned(),
                osk_ed_pub: [3u8; 32],
                cross_sig: [4u8; 64],
                ca_priv: [5u8; 32],
            },
            prekey_bundle: PrekeyBundle {
                spk_x_pub: [6u8; 32],
                spk_sig: [7u8; 64],
                pqspk_ek: Vec::new(),
                pqspk_sig: [9u8; 64],
                opk_x_pub: None,
                pqopk_ek: None,
            },
            invite_nonce: [10u8; INVITE_NONCE_LEN],
            expires_at: 0,
            sig: [11u8; 64],
        };
        let s = format!("{inv:?}");
        assert_eq!(s, "Invitation(redacted)");
        assert!(!s.contains("geheimeadresse"));
        assert_eq!(
            format!("{:?}", inv.compartment),
            "CompartmentPart(redacted)"
        );
    }
}
