//! `Envelope` — Außenhülle einer zugestellten Nachricht, plus `Payload`.
//!
//! Normativ: `spec/protokoll-spec.md` §8:
//!
//! ```text
//! Envelope {
//!   transport_tag: 8B         // EPHEMER pro Transport
//!   dr_header: { dh_pub, pn, n }
//!   ciphertext                // AEAD(mk, nonce, ad=H(dr_header), pt=Payload)
//! }
//! ```
//!
//! Die Hülle ist für `vault-transport` opak: die Transportschicht kennt nach
//! `spec/engineering-setup.md` §2 keine Klartext-Payloads.
//!
//! `transport_tag` wird **pro Transport frisch gezogen** (§8, §13) und darf
//! niemals über Transportgrenzen hinweg stabil sein — sonst entsteht genau
//! die Cross-Transport-Korrelation, die `gesamtkonzept.md` §2.8 ausschließt.
//!
//! # Feldnummerierung
//!
//! Wie in [`crate::invitation`] eine Implementierungsfestlegung, kein
//! Spec-Inhalt; **GATE-6** ist offen.

use crate::codec::{Decoder, Encoder};
use crate::error::WireError;

/// Länge von `transport_tag` in Bytes (§8: 8 B).
pub const TRANSPORT_TAG_LEN: usize = 8;

/// `dr_header` aus §8.
///
/// Spiegelt `vault_crypto::ratchet::Header`. `vault-wire` hängt bewusst
/// **nicht** von `vault-crypto` ab — die Schichtregel erlaubt es zwar, aber
/// eine Kopplung des Wire-Formats an die Kryptobibliothek wäre eine
/// unnötige Abhängigkeitsrichtung.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DrHeader {
    /// Öffentlicher DH-Ratchet-Schlüssel des Senders.
    pub dh_pub: [u8; 32],
    /// Anzahl Nachrichten der vorherigen Sendekette.
    pub pn: u32,
    /// Laufende Nummer in der aktuellen Sendekette.
    pub n: u32,
}

/// Aussenhuelle nach §8.
///
/// Redigiertes `Debug` (`CLAUDE.md`).
#[derive(Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Ephemeres Transport-Tag, nur zur Frame-Zuordnung.
    pub transport_tag: [u8; TRANSPORT_TAG_LEN],
    /// Double-Ratchet-Header.
    pub dr_header: DrHeader,
    /// AEAD-Chiffrat der [`Payload`].
    pub ciphertext: Vec<u8>,
}

/// Nachrichteninhalt nach §8.
///
/// Vollständig kodiert sind die Varianten, deren Felder §8 benennt. Die
/// übrigen fünf Varianten sind an anderer Stelle spezifiziert (§5, §9, §11,
/// `gruppen-spec.md`) und werden hier als **rohe, bereits kanonisch kodierte
/// CBOR-Bytes** durchgereicht, statt ihre Feldstruktur zu erfinden.
#[derive(Clone, PartialEq, Eq)]
pub enum Payload {
    /// `Text { body, ttl }` — `ttl` in Sekunden (selbstlöschend, MS-3).
    Text {
        /// Nachrichtentext.
        body: String,
        /// Lebensdauer in Sekunden.
        ttl: u64,
    },
    /// `Attachment { key, size, chunk_count, manifest_hash }`.
    Attachment {
        /// XChaCha20-Schlüssel der Chunks.
        key: [u8; 32],
        /// Gesamtgröße in Bytes.
        size: u64,
        /// Anzahl Chunks.
        chunk_count: u64,
        /// Hash über das Manifest.
        manifest_hash: [u8; 32],
    },
    /// `Ack { msg_id }` — setzt den Status `delivered` (§9.4).
    Ack {
        /// `msg_id = H(dr_header ‖ ciphertext)`.
        msg_id: [u8; 32],
    },
    /// `Receipt { msg_id, kind }`.
    Receipt {
        /// Betroffene Nachricht.
        msg_id: [u8; 32],
        /// Art der Quittung.
        kind: ReceiptKind,
    },
    /// Variante, deren Feldstruktur außerhalb von §8 spezifiziert ist.
    Other {
        /// Variantenkennung (siehe [`Payload::variant_tag`]).
        tag: u64,
        /// Bereits kanonisch kodierter CBOR-Körper.
        body: Vec<u8>,
    },
}

/// Art einer Quittung (§8: `DELIVERED|READ`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptKind {
    /// Zugestellt.
    Delivered,
    /// Gelesen — opt-in (§8).
    Read,
}

impl Payload {
    /// Variantenkennung auf der Wire.
    ///
    /// 0–3 sind die in §8 vollständig spezifizierten Varianten; 4–8 sind
    /// `ContactCard`, `DeviceListUpdate`, `SyncRecord`, `GroupCtrl` und
    /// `RevocationNotice` in der Reihenfolge ihrer Aufzählung in §8.
    #[must_use]
    pub fn variant_tag(&self) -> u64 {
        match self {
            Self::Text { .. } => 0,
            Self::Attachment { .. } => 1,
            Self::Ack { .. } => 2,
            Self::Receipt { .. } => 3,
            Self::Other { tag, .. } => *tag,
        }
    }

    /// Kodiert deterministisch nach CBOR.
    ///
    /// # Fehler
    ///
    /// Fehler aus [`Encoder::finish`].
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut e = Encoder::new();
        e.array(2);
        e.u64(self.variant_tag());
        match self {
            Self::Text { body, ttl } => {
                e.array(2);
                e.text(body);
                e.u64(*ttl);
            }
            Self::Attachment {
                key,
                size,
                chunk_count,
                manifest_hash,
            } => {
                e.array(4);
                e.bytes(key);
                e.u64(*size);
                e.u64(*chunk_count);
                e.bytes(manifest_hash);
            }
            Self::Ack { msg_id } => {
                e.array(1);
                e.bytes(msg_id);
            }
            Self::Receipt { msg_id, kind } => {
                e.array(2);
                e.bytes(msg_id);
                e.u64(match kind {
                    ReceiptKind::Delivered => 0,
                    ReceiptKind::Read => 1,
                });
            }
            Self::Other { body, .. } => {
                e.bytes(body);
            }
        }
        e.finish()
    }

    /// Liest eine Payload.
    ///
    /// # Fehler
    ///
    /// * [`WireError::UnknownVariant`] — Variantenkennung > 8.
    /// * [`WireError::FieldMismatch`] — Feldzahl passt nicht.
    /// * weitere Fehler aus [`crate::codec`].
    pub fn decode(input: &[u8]) -> Result<Self, WireError> {
        let mut d = Decoder::new(input)?;
        if d.array_len()? != 2 {
            return Err(WireError::FieldMismatch);
        }
        let tag = d.u64()?;
        let payload = match tag {
            0 => {
                expect_array(&mut d, 2)?;
                Self::Text {
                    body: d.text()?.to_owned(),
                    ttl: d.u64()?,
                }
            }
            1 => {
                expect_array(&mut d, 4)?;
                Self::Attachment {
                    key: d.byte_array::<32>()?,
                    size: d.u64()?,
                    chunk_count: d.u64()?,
                    manifest_hash: d.byte_array::<32>()?,
                }
            }
            2 => {
                expect_array(&mut d, 1)?;
                Self::Ack {
                    msg_id: d.byte_array::<32>()?,
                }
            }
            3 => {
                expect_array(&mut d, 2)?;
                let msg_id = d.byte_array::<32>()?;
                let kind = match d.u64()? {
                    0 => ReceiptKind::Delivered,
                    1 => ReceiptKind::Read,
                    _ => return Err(WireError::UnknownVariant),
                };
                Self::Receipt { msg_id, kind }
            }
            4..=8 => Self::Other {
                tag,
                body: d.bytes()?.to_vec(),
            },
            _ => return Err(WireError::UnknownVariant),
        };
        d.finish()?;
        Ok(payload)
    }
}

impl Envelope {
    /// Kodiert deterministisch nach CBOR.
    ///
    /// # Fehler
    ///
    /// Fehler aus [`Encoder::finish`].
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut e = Encoder::new();
        e.map(3);
        e.u64(0);
        e.bytes(&self.transport_tag);
        e.u64(1);
        e.array(3);
        e.bytes(&self.dr_header.dh_pub);
        e.u64(u64::from(self.dr_header.pn));
        e.u64(u64::from(self.dr_header.n));
        e.u64(2);
        e.bytes(&self.ciphertext);
        e.finish()
    }

    /// Liest eine Hülle.
    ///
    /// # Fehler
    ///
    /// * [`WireError::FieldMismatch`] — Feldzahl oder Schlüssel passen nicht.
    /// * weitere Fehler aus [`crate::codec`].
    pub fn decode(input: &[u8]) -> Result<Self, WireError> {
        let mut d = Decoder::new(input)?;
        if d.map_len()? != 3 {
            return Err(WireError::FieldMismatch);
        }
        expect_key(&mut d, 0)?;
        let transport_tag = d.byte_array::<TRANSPORT_TAG_LEN>()?;

        expect_key(&mut d, 1)?;
        expect_array(&mut d, 3)?;
        let dh_pub = d.byte_array::<32>()?;
        let pn = d.u32()?;
        let n = d.u32()?;

        expect_key(&mut d, 2)?;
        let ciphertext = d.bytes()?.to_vec();

        d.finish()?;
        Ok(Self {
            transport_tag,
            dr_header: DrHeader { dh_pub, pn, n },
            ciphertext,
        })
    }
}

fn expect_array(d: &mut Decoder<'_>, len: usize) -> Result<(), WireError> {
    if d.array_len()? == len {
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "Testcode"
)]
mod tests {
    use super::*;

    fn beispiel() -> Envelope {
        Envelope {
            transport_tag: [1u8; TRANSPORT_TAG_LEN],
            dr_header: DrHeader {
                dh_pub: [2u8; 32],
                pn: 7,
                n: 42,
            },
            ciphertext: vec![3u8; 128],
        }
    }

    #[test]
    fn envelope_roundtrip() {
        let env = beispiel();
        assert_eq!(Envelope::decode(&env.encode().unwrap()).unwrap(), env);
    }

    #[test]
    fn envelope_kodierung_ist_deterministisch() {
        let env = beispiel();
        let erste = env.encode().unwrap();
        for _ in 0..50 {
            assert_eq!(env.encode().unwrap(), erste);
        }
    }

    #[test]
    fn payload_roundtrip_alle_spezifizierten_varianten() {
        let faelle = vec![
            Payload::Text {
                body: "hallo".to_owned(),
                ttl: 86_400,
            },
            Payload::Attachment {
                key: [4u8; 32],
                size: 1024,
                chunk_count: 4,
                manifest_hash: [5u8; 32],
            },
            Payload::Ack { msg_id: [6u8; 32] },
            Payload::Receipt {
                msg_id: [7u8; 32],
                kind: ReceiptKind::Delivered,
            },
            Payload::Receipt {
                msg_id: [8u8; 32],
                kind: ReceiptKind::Read,
            },
            Payload::Other {
                tag: 6,
                body: vec![9u8; 16],
            },
        ];
        for p in faelle {
            let bytes = p.encode().unwrap();
            assert_eq!(Payload::decode(&bytes).unwrap(), p);
        }
    }

    #[test]
    fn unbekannte_variante_wird_abgewiesen() {
        let mut e = Encoder::new();
        e.array(2);
        e.u64(99);
        e.bytes(b"x");
        let bytes = e.finish().unwrap();
        assert_eq!(Payload::decode(&bytes), Err(WireError::UnknownVariant));
    }

    #[test]
    fn nicht_kanonische_eingabe_wird_abgewiesen() {
        assert_eq!(
            Envelope::decode(&[0x18, 0x17]),
            Err(WireError::NonMinimalHead)
        );
        assert_eq!(
            Payload::decode(&[0x18, 0x17]),
            Err(WireError::NonMinimalHead)
        );
    }

    #[test]
    fn restbytes_werden_abgewiesen() {
        let mut bytes = beispiel().encode().unwrap();
        bytes.push(0x00);
        assert!(Envelope::decode(&bytes).is_err());
    }

    #[test]
    fn transport_tag_falscher_laenge_wird_abgewiesen() {
        let mut e = Encoder::new();
        e.map(3);
        e.u64(0);
        e.bytes(&[1u8; 9]); // 9 statt 8
        e.u64(1);
        e.array(3);
        e.bytes(&[2u8; 32]);
        e.u64(0);
        e.u64(0);
        e.u64(2);
        e.bytes(b"");
        let bytes = e.finish().unwrap();
        assert_eq!(Envelope::decode(&bytes), Err(WireError::ValueOutOfRange));
    }

    #[test]
    fn leeres_chiffrat_ist_zulaessig() {
        let mut env = beispiel();
        env.ciphertext = Vec::new();
        assert_eq!(Envelope::decode(&env.encode().unwrap()).unwrap(), env);
    }
}

impl core::fmt::Debug for DrHeader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DrHeader(redacted)")
    }
}

impl core::fmt::Debug for Envelope {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Envelope(redacted)")
    }
}

impl core::fmt::Debug for Payload {
    /// Gibt nur die Variante preis, niemals Inhalte — `Payload::Text` traegt
    /// den Klartext einer Nachricht (`CLAUDE.md`: keine Klartexte in Logs).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Payload::tag({})(redacted)", self.variant_tag())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "Testcode")]
mod debug_tests {
    use super::*;

    #[test]
    fn debug_gibt_keinen_klartext_preis() {
        let p = Payload::Text {
            body: "streng geheim".to_owned(),
            ttl: 60,
        };
        let s = format!("{p:?}");
        assert!(!s.contains("geheim"), "Klartext im Debug-Output: {s}");

        let env = Envelope {
            transport_tag: [1u8; TRANSPORT_TAG_LEN],
            dr_header: DrHeader {
                dh_pub: [2u8; 32],
                pn: 0,
                n: 0,
            },
            ciphertext: Vec::new(),
        };
        assert_eq!(format!("{env:?}"), "Envelope(redacted)");
    }
}
