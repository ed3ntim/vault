//! Double Ratchet für alle 1:1-Nachrichten (CR-2).
//!
//! Normativ: `spec/protokoll-spec.md` §8 („**Double Ratchet** wie
//! Signal-Spezifikation, initialisiert aus PQXDH-`SK`. Pro Nachricht
//! DH-Ratchet bei Richtungswechsel, symmetrischer Ratchet je Nachricht"),
//! §2 (Zustand `DR_X`: `RK, CKs, CKr, DHs, DHr, Nr, Ns, PN, skipped[]`),
//! `spec/gesamtkonzept.md` §2.4. ADR-05: Verfahren nach Signal-Spezifikation,
//! Primitive aus etablierten Bibliotheken.
//!
//! # Zwei bewusste Festlegungen, die die Spec offenlässt
//!
//! 1. **Kodierung von `dr_header` für `ad`.** §8 verlangt
//!    `ad = H(dr_header)`, legt die Byte-Kodierung des Headers aber nicht
//!    fest. Hier gilt die feste 40-Byte-Form `dh_pub ‖ pn ‖ n` mit
//!    `u32`-Feldern little-endian (§1: „Alle Multi-Byte-Felder
//!    little-endian"). Sie ist eindeutig, weil alle drei Felder feste Länge
//!    haben. Die Wire-Kodierung des Envelope bleibt davon unberührt und
//!    gehört nach `vault-wire`.
//! 2. **Woher der neue DH-Schlüssel kommt.** Ein DH-Ratchet-Schritt braucht
//!    ein frisches Schlüsselpaar. `vault-crypto` erzeugt selbst keine
//!    Zufallszahlen: das unterliegt dem Entropie-Gate
//!    (`spec/gesamtkonzept.md` §2.1, ID-2), und I/O ist hier nach der
//!    Schichtregel verboten (Gate G-5). [`Ratchet::decrypt`] nimmt deshalb
//!    das nächste Schlüsselpaar als Parameter entgegen.
//!
//! Beide Punkte sind Implementierungsentscheidungen, keine Spec-Änderungen —
//! sie sind zur Bestätigung vorgelegt (siehe `TAGESBERICHT.md`).

use std::collections::{BTreeMap, VecDeque};

use crate::aead;
use crate::dh::{DhPrivate, DhPublic, X25519_LEN};
use crate::error::CryptoError;
use crate::hash;
use crate::kdf::{self, ChainKey, MessageKey, RootKey};

/// Obergrenze der Nachrichten, die innerhalb **einer** Kette übersprungen
/// werden dürfen.
pub const MAX_SKIP_PER_CHAIN: u32 = 1000;

/// Obergrenze der insgesamt vorgehaltenen `skipped_message_keys` je Session.
///
/// `spec/phase0-spikeplan.md` §2 (S2) nennt „`skipped_message_keys` < 1000 pro
/// Session (Speicherobergrenze)" als Erfolgskriterium — der Wert stammt also
/// aus der Spec, nicht aus eigener Festlegung. Das Kriterium ist **echt
/// kleiner** als 1000, deshalb steht hier 999 und nicht 1000.
pub const MAX_SKIPPED_STORED: usize = 999;

/// Länge der `ad`-Kodierung eines Headers in Bytes.
pub const HEADER_AD_LEN: usize = 40;

/// Info-String der Message-Key-Aufspaltung.
const INFO_MSG: &[u8] = b"vault-dr-msg";

/// `dr_header` aus `spec/protokoll-spec.md` §8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Öffentlicher DH-Ratchet-Schlüssel des Senders.
    pub dh_pub: DhPublic,
    /// Anzahl Nachrichten der vorherigen Sendekette.
    pub pn: u32,
    /// Laufende Nummer in der aktuellen Sendekette.
    pub n: u32,
}

impl Header {
    /// Feste Byte-Kodierung für die Berechnung von `ad = H(dr_header)`.
    #[must_use]
    pub fn encode_for_ad(&self) -> [u8; HEADER_AD_LEN] {
        let mut out = [0u8; HEADER_AD_LEN];
        let (key_part, rest) = out.split_at_mut(X25519_LEN);
        key_part.copy_from_slice(self.dh_pub.as_bytes());
        let (pn_part, n_part) = rest.split_at_mut(4);
        pn_part.copy_from_slice(&self.pn.to_le_bytes());
        n_part.copy_from_slice(&self.n.to_le_bytes());
        out
    }

    /// `ad = H(dr_header)` nach §8.
    #[must_use]
    pub fn associated_data(&self) -> [u8; hash::HASH_LEN] {
        hash::h(&self.encode_for_ad())
    }
}

/// Double-Ratchet-Zustand einer Kontakt-Session (`DR_X` aus §2).
///
/// Nach `spec/protokoll-spec.md` §9.3 (Primärgerät-Modell, ADR-17) existiert
/// dieser Zustand je Kontakt **genau einmal** und liegt ausschließlich auf dem
/// Primärgerät.
#[derive(Debug)]
pub struct Ratchet {
    rk: RootKey,
    dhs: DhPrivate,
    dhr: Option<DhPublic>,
    cks: Option<ChainKey>,
    ckr: Option<ChainKey>,
    ns: u32,
    nr: u32,
    pn: u32,
    skipped: BTreeMap<(DhPublic, u32), MessageKey>,
    /// Einfügereihenfolge für die FIFO-Verdrängung (ADR-19, Entwurf).
    ///
    /// Maßgeblich ist die Reihenfolge des Einfügens, **nicht** die
    /// Nachrichtennummer: Nach einem DH-Ratchet-Schritt beginnen die Nummern
    /// wieder bei 0, eine Sortierung nach Nummer würde die falschen Einträge
    /// verdrängen.
    skipped_order: VecDeque<(DhPublic, u32)>,
}

impl Ratchet {
    /// Initialisiert die Seite, die **zuerst sendet**.
    ///
    /// Entspricht dem Initiator aus `spec/protokoll-spec.md` §5, der `SK` aus
    /// PQXDH bereits kennt und den `SPK` der Gegenseite besitzt.
    ///
    /// # Fehler
    ///
    /// [`CryptoError::InvalidKeyLength`], wenn die DH-Operation kein
    /// beitragendes Ergebnis liefert.
    pub fn init_initiator(
        sk: RootKey,
        our_dh: DhPrivate,
        their_dh: DhPublic,
    ) -> Result<Self, CryptoError> {
        let dh_out = our_dh.diffie_hellman(&their_dh)?;
        let (rk, cks) = kdf::kdf_rk(&sk, &dh_out)?;
        Ok(Self {
            rk,
            dhs: our_dh,
            dhr: Some(their_dh),
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: BTreeMap::new(),
            skipped_order: VecDeque::new(),
        })
    }

    /// Initialisiert die Seite, die **zuerst empfängt**.
    ///
    /// `our_dh` ist der Schlüssel, dessen öffentlicher Teil der Gegenseite
    /// vorliegt (`SPK` aus §2).
    #[must_use]
    pub fn init_responder(sk: RootKey, our_dh: DhPrivate) -> Self {
        Self {
            rk: sk,
            dhs: our_dh,
            dhr: None,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: BTreeMap::new(),
            skipped_order: VecDeque::new(),
        }
    }

    /// Anzahl aktuell vorgehaltener übersprungener Message Keys.
    #[must_use]
    pub fn skipped_len(&self) -> usize {
        self.skipped.len()
    }

    /// Verschlüsselt eine Nachricht und schreitet den symmetrischen Ratchet
    /// um einen Schritt fort.
    ///
    /// # Fehler
    ///
    /// * [`CryptoError::RatchetStateInvalid`] — es existiert noch keine
    ///   Sendekette (die empfangende Seite muss erst eine Nachricht erhalten).
    /// * [`CryptoError::AeadSealFailed`] aus der AEAD-Schicht.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(Header, Vec<u8>), CryptoError> {
        let cks = self.cks.as_ref().ok_or(CryptoError::RatchetStateInvalid)?;
        let (next_ck, mk) = kdf::kdf_ck(cks)?;

        let header = Header {
            dh_pub: self.dhs.public(),
            pn: self.pn,
            n: self.ns,
        };
        let (key, nonce) = derive_message_keys(&mk)?;
        let ciphertext = aead::seal(&key, &nonce, &header.associated_data(), plaintext)?;

        self.cks = Some(next_ck);
        self.ns = self
            .ns
            .checked_add(1)
            .ok_or(CryptoError::RatchetStateInvalid)?;
        Ok((header, ciphertext))
    }

    /// Entschlüsselt eine Nachricht.
    ///
    /// `next_dh` wird **nur** verbraucht, wenn ein DH-Ratchet-Schritt nötig
    /// ist (Richtungswechsel). Der Aufrufer liefert ein frisches Paar, weil
    /// die Schlüsselerzeugung dem Entropie-Gate unterliegt und `vault-crypto`
    /// kein I/O machen darf (siehe Modul-Dokumentation).
    ///
    /// **Try-then-commit:** Der eigene Zustand wird erst geändert, wenn das
    /// AEAD den Header *und* das Chiffrat authentifiziert hat. Ein
    /// eingeschleuster oder wiederholt zugestellter Frame kann die Session
    /// deshalb nicht beschädigen — er kostet Rechenzeit und wird verworfen.
    /// Der Signal-Referenz-Pseudocode mutiert an dieser Stelle früher; das
    /// wäre ein Verfügbarkeitsangriff mit Aufwand „ein Frame"
    /// (`spec/threat-model.md` A7/G8).
    ///
    /// # Fehler
    ///
    /// * [`CryptoError::SkippedKeyLimitExceeded`] — die Lücke überschreitet
    ///   [`MAX_SKIP_PER_CHAIN`] oder der Vorrat [`MAX_SKIPPED_STORED`].
    /// * [`CryptoError::AeadOpenFailed`] — Chiffrat oder `ad` passen nicht,
    ///   oder der Message Key war bereits verbraucht (Forward Secrecy).
    /// * [`CryptoError::RatchetStateInvalid`] — Zähler übergelaufen oder
    ///   Empfangskette fehlt.
    pub fn decrypt(
        &mut self,
        header: &Header,
        ciphertext: &[u8],
        next_dh: DhPrivate,
    ) -> Result<Vec<u8>, CryptoError> {
        // 1. Bereits übersprungener Message Key. Erst nach erfolgreicher
        //    Authentifikation entfernen, damit ein manipuliertes Chiffrat den
        //    Schlüssel nicht vernichtet.
        if let Some(mk) = self.skipped.get(&(header.dh_pub, header.n)) {
            let plaintext = open_with(mk, header, ciphertext)?;
            let key = (header.dh_pub, header.n);
            self.skipped.remove(&key);
            self.skipped_order.retain(|entry| entry != &key);
            return Ok(plaintext);
        }

        // 2. Alles Weitere auf einer Arbeitskopie rechnen.
        let mut work = Working {
            rk: self.rk.clone(),
            dhs: self.dhs.clone(),
            dhr: self.dhr,
            cks: self.cks.clone(),
            ckr: self.ckr.clone(),
            ns: self.ns,
            nr: self.nr,
            pn: self.pn,
        };
        let mut staged: Vec<((DhPublic, u32), MessageKey)> = Vec::new();

        if work.dhr != Some(header.dh_pub) {
            skip_message_keys(&mut work, header.pn, &mut staged, self.skipped.len())?;
            dh_ratchet(&mut work, header, next_dh)?;
        }
        skip_message_keys(&mut work, header.n, &mut staged, self.skipped.len())?;

        let ckr = work.ckr.as_ref().ok_or(CryptoError::RatchetStateInvalid)?;
        let (next_ck, mk) = kdf::kdf_ck(ckr)?;

        // 3. Authentifikation. Ab hier ist der Frame echt.
        let plaintext = open_with(&mk, header, ciphertext)?;

        // 4. Commit.
        work.ckr = Some(next_ck);
        work.nr = work
            .nr
            .checked_add(1)
            .ok_or(CryptoError::RatchetStateInvalid)?;
        self.rk = work.rk;
        self.dhs = work.dhs;
        self.dhr = work.dhr;
        self.cks = work.cks;
        self.ckr = work.ckr;
        self.ns = work.ns;
        self.nr = work.nr;
        self.pn = work.pn;
        for (key, value) in staged {
            self.insert_skipped(key, value);
        }
        Ok(plaintext)
    }

    /// Legt einen übersprungenen Message Key ab und verdrängt dabei nach
    /// FIFO, wenn der Vorrat voll ist (ADR-19, Entwurf).
    ///
    /// Wird ausschließlich aus dem Commit-Pfad von [`Ratchet::decrypt`]
    /// aufgerufen, also **nach** erfolgreicher Authentifikation. Ein
    /// eingeschleuster Frame kann damit keine Verdrängung auslösen — der
    /// Angreifer aus Befund HOCH-2 müsste echte Nachrichten unterschlagen,
    /// statt eigene einzuspeisen.
    fn insert_skipped(&mut self, key: (DhPublic, u32), value: MessageKey) {
        while self.skipped.len() >= MAX_SKIPPED_STORED {
            match self.skipped_order.pop_front() {
                Some(oldest) => {
                    // Der verdrängte Message Key wird hier gelöscht
                    // (`ZeroizeOnDrop`), statt bis zu seiner Einlösung
                    // liegen zu bleiben.
                    self.skipped.remove(&oldest);
                }
                None => break,
            }
        }
        if self.skipped.insert(key, value).is_none() {
            self.skipped_order.push_back(key);
        }
    }
}

/// Arbeitskopie des Zustands für [`Ratchet::decrypt`].
struct Working {
    rk: RootKey,
    dhs: DhPrivate,
    dhr: Option<DhPublic>,
    cks: Option<ChainKey>,
    ckr: Option<ChainKey>,
    ns: u32,
    nr: u32,
    pn: u32,
}

fn dh_ratchet(work: &mut Working, header: &Header, next_dh: DhPrivate) -> Result<(), CryptoError> {
    // Beide DH-Operationen und beide Ableitungen zuerst rechnen: schlägt eine
    // fehl (z. B. Punkt kleiner Ordnung im Header), bleibt die Arbeitskopie
    // unverändert und der Aufrufer verwirft sie.
    let dh_out_recv = work.dhs.diffie_hellman(&header.dh_pub)?;
    let (rk_recv, ckr) = kdf::kdf_rk(&work.rk, &dh_out_recv)?;
    let dh_out_send = next_dh.diffie_hellman(&header.dh_pub)?;
    let (rk_send, cks) = kdf::kdf_rk(&rk_recv, &dh_out_send)?;

    work.pn = work.ns;
    work.ns = 0;
    work.nr = 0;
    work.dhr = Some(header.dh_pub);
    work.rk = rk_send;
    work.ckr = Some(ckr);
    work.cks = Some(cks);
    work.dhs = next_dh;
    Ok(())
}

fn skip_message_keys(
    work: &mut Working,
    until: u32,
    staged: &mut Vec<((DhPublic, u32), MessageKey)>,
    already_stored: usize,
) -> Result<(), CryptoError> {
    if work.ckr.is_none() {
        return Ok(());
    }
    let gap = until.saturating_sub(work.nr);
    if gap > MAX_SKIP_PER_CHAIN {
        return Err(CryptoError::SkippedKeyLimitExceeded);
    }
    let dhr = work.dhr.ok_or(CryptoError::RatchetStateInvalid)?;

    while work.nr < until {
        let ckr = work.ckr.as_ref().ok_or(CryptoError::RatchetStateInvalid)?;
        let (next_ck, mk) = kdf::kdf_ck(ckr)?;
        // Kein Abbruch mehr bei vollem Vorrat: die Verdrängung nach ADR-19
        // passiert beim Commit in `insert_skipped`. Ein Abbruch hier war der
        // Befund HOCH-2 — er machte die Session dauerhaft unbrauchbar.
        // `staged` bleibt durch MAX_SKIP_PER_CHAIN oben gedeckelt.
        let _ = already_stored;
        staged.push(((dhr, work.nr), mk));
        work.ckr = Some(next_ck);
        work.nr = work
            .nr
            .checked_add(1)
            .ok_or(CryptoError::RatchetStateInvalid)?;
    }
    Ok(())
}

fn open_with(mk: &MessageKey, header: &Header, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let (key, nonce) = derive_message_keys(mk)?;
    aead::open(&key, &nonce, &header.associated_data(), ciphertext)
}

/// Spaltet einen Message Key in AEAD-Schlüssel und Nonce auf.
fn derive_message_keys(
    mk: &MessageKey,
) -> Result<([u8; aead::AEAD_KEY_LEN], [u8; aead::NONCE_LEN]), CryptoError> {
    let mut okm = [0u8; 56];
    kdf::hkdf_sha256(None, mk.as_bytes(), INFO_MSG, &mut okm)?;
    let mut key = [0u8; aead::AEAD_KEY_LEN];
    let mut nonce = [0u8; aead::NONCE_LEN];
    let (k, n) = okm.split_at(aead::AEAD_KEY_LEN);
    key.copy_from_slice(k);
    nonce.copy_from_slice(n);
    Ok((key, nonce))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    reason = "Testcode"
)]
mod tests {
    use super::*;

    /// Deterministischer Pseudozufall für reproduzierbare Tests. Kein
    /// Kryptomaterial — nur Testreihenfolgen und Testschlüssel.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            self.0
        }
        fn key(&mut self) -> DhPrivate {
            let mut b = [0u8; 32];
            for chunk in b.chunks_mut(8) {
                let v = self.next().to_le_bytes();
                let take = chunk.len();
                chunk.copy_from_slice(&v[..take]);
            }
            DhPrivate::from_bytes(b)
        }
    }

    fn paar() -> (Ratchet, Ratchet, Lcg) {
        let mut rng = Lcg(0x5EED);
        let sk = RootKey::from_bytes([5u8; 32]);
        let bob_spk = rng.key();
        let alice = Ratchet::init_initiator(sk.clone(), rng.key(), bob_spk.public()).unwrap();
        let bob = Ratchet::init_responder(sk, bob_spk);
        (alice, bob, rng)
    }

    #[test]
    fn roundtrip_einzelne_nachricht() {
        let (mut a, mut b, mut rng) = paar();
        let (h, ct) = a.encrypt(b"hallo").unwrap();
        assert_eq!(b.decrypt(&h, &ct, rng.key()).unwrap(), b"hallo");
    }

    #[test]
    fn mehrere_nachrichten_in_folge() {
        let (mut a, mut b, mut rng) = paar();
        for i in 0..50u32 {
            let pt = format!("nachricht {i}");
            let (h, ct) = a.encrypt(pt.as_bytes()).unwrap();
            assert_eq!(h.n, i);
            assert_eq!(b.decrypt(&h, &ct, rng.key()).unwrap(), pt.as_bytes());
        }
        assert_eq!(b.skipped_len(), 0, "in Reihenfolge: nichts zu speichern");
    }

    #[test]
    fn richtungswechsel_loest_dh_ratchet_aus() {
        let (mut a, mut b, mut rng) = paar();
        let (h1, ct1) = a.encrypt(b"a1").unwrap();
        b.decrypt(&h1, &ct1, rng.key()).unwrap();

        let (h2, ct2) = b.encrypt(b"b1").unwrap();
        assert_ne!(
            h2.dh_pub, h1.dh_pub,
            "nach dem Ratchet-Schritt muss ein neuer DH-Schluessel gelten"
        );
        assert_eq!(a.decrypt(&h2, &ct2, rng.key()).unwrap(), b"b1");

        let (h3, ct3) = a.encrypt(b"a2").unwrap();
        assert_ne!(h3.dh_pub, h1.dh_pub);
        assert_eq!(b.decrypt(&h3, &ct3, rng.key()).unwrap(), b"a2");
    }

    #[test]
    fn out_of_order_innerhalb_einer_kette() {
        let (mut a, mut b, mut rng) = paar();
        let m: Vec<_> = (0..5)
            .map(|i| a.encrypt(format!("m{i}").as_bytes()).unwrap())
            .collect();

        assert_eq!(b.decrypt(&m[4].0, &m[4].1, rng.key()).unwrap(), b"m4");
        assert_eq!(b.skipped_len(), 4);
        for i in [2usize, 0, 3, 1] {
            assert_eq!(
                b.decrypt(&m[i].0, &m[i].1, rng.key()).unwrap(),
                format!("m{i}").as_bytes()
            );
        }
        assert_eq!(b.skipped_len(), 0, "alle Luecken geschlossen");
    }

    #[test]
    fn out_of_order_ueber_einen_ratchet_schritt_hinweg() {
        let (mut a, mut b, mut rng) = paar();
        let alt: Vec<_> = (0..3)
            .map(|i| a.encrypt(format!("alt{i}").as_bytes()).unwrap())
            .collect();

        b.decrypt(&alt[0].0, &alt[0].1, rng.key()).unwrap();
        let (hb, ctb) = b.encrypt(b"antwort").unwrap();
        a.decrypt(&hb, &ctb, rng.key()).unwrap();
        let (hneu, ctneu) = a.encrypt(b"neu").unwrap();

        assert_eq!(b.decrypt(&hneu, &ctneu, rng.key()).unwrap(), b"neu");
        assert_eq!(b.decrypt(&alt[1].0, &alt[1].1, rng.key()).unwrap(), b"alt1");
        assert_eq!(b.decrypt(&alt[2].0, &alt[2].1, rng.key()).unwrap(), b"alt2");
    }

    #[test]
    fn replay_schlaegt_fehl() {
        let (mut a, mut b, mut rng) = paar();
        let (h, ct) = a.encrypt(b"einmal").unwrap();
        assert_eq!(b.decrypt(&h, &ct, rng.key()).unwrap(), b"einmal");
        assert!(
            b.decrypt(&h, &ct, rng.key()).is_err(),
            "verbrauchter Message Key darf nicht erneut oeffnen"
        );
    }

    #[test]
    fn manipuliertes_chiffrat_schlaegt_fehl() {
        let (mut a, mut b, mut rng) = paar();
        let (h, mut ct) = a.encrypt(b"unversehrt").unwrap();
        ct[0] ^= 0x01;
        assert_eq!(
            b.decrypt(&h, &ct, rng.key()),
            Err(CryptoError::AeadOpenFailed)
        );
    }

    #[test]
    fn manipulierter_header_schlaegt_fehl() {
        let (mut a, mut b, mut rng) = paar();
        let (mut h, ct) = a.encrypt(b"pt").unwrap();
        h.pn = h.pn.wrapping_add(1); // ad = H(dr_header) aendert sich
        assert_eq!(
            b.decrypt(&h, &ct, rng.key()),
            Err(CryptoError::AeadOpenFailed)
        );
    }

    #[test]
    fn kappungsgrenze_je_kette_haelt() {
        let (mut a, mut b, mut rng) = paar();
        for _ in 0..=MAX_SKIP_PER_CHAIN {
            let _ = a.encrypt(b"weg").unwrap();
        }
        let (h, ct) = a.encrypt(b"zu weit").unwrap();
        assert_eq!(
            b.decrypt(&h, &ct, rng.key()),
            Err(CryptoError::SkippedKeyLimitExceeded)
        );
        assert!(
            b.skipped_len() <= MAX_SKIPPED_STORED,
            "Speicherobergrenze darf nie ueberschritten werden"
        );
    }

    /// Der Vorrat darf **nie** über [`MAX_SKIPPED_STORED`] wachsen.
    ///
    /// Diese Eigenschaft ist unabhängig von der Verdrängungspolitik und gilt
    /// vor wie nach ADR-19.
    #[test]
    fn speicherobergrenze_wird_nie_ueberschritten() {
        let (mut a, mut b, mut rng) = paar();
        for _ in 0..3 {
            for _ in 0..600 {
                let _ = a.encrypt(b"x").unwrap();
            }
            let (h, ct) = a.encrypt(b"trigger").unwrap();
            let _ = b.decrypt(&h, &ct, rng.key());
            assert!(
                b.skipped_len() <= MAX_SKIPPED_STORED,
                "Vorrat ueberschritten: {}",
                b.skipped_len()
            );
        }
    }

    /// Regression zu **HOCH-2** des unabhängigen Gegenlesens.
    ///
    /// Der Vorgängertest feierte das Erreichen der Obergrenze als Erfolg und
    /// kehrte zurück, ohne zu prüfen, ob die Session danach noch benutzbar
    /// ist — er kodifizierte damit genau die Verklemmung als korrektes
    /// Verhalten.
    ///
    /// Gemessener Angriff: Ein Angreifer unterschlägt einmalig
    /// [`MAX_SKIPPED_STORED`] Frames. Danach ist der Vorrat voll und schrumpft
    /// nur noch, wenn die unterschlagenen Nachrichten doch noch eintreffen —
    /// was sie nie tun. Ab da scheitert **jede** weitere Nachricht mit einer
    /// Lücke, dauerhaft. Aufwand einmalig, Wirkung permanent
    /// (`spec/threat-model.md` A7/G8, dort als ○ geführt).
    ///
    /// **Dieser Test ist gegen den nicht-verdrängenden Stand rot.** Er
    /// dokumentiert HOCH-2, bis die FIFO-Verdrängung aus ADR-19 ihn grün
    /// macht.
    #[test]
    fn voller_store_blockiert_die_session_nicht() {
        let (mut a, mut b, mut rng) = paar();

        // Den Vorrat bis zur Obergrenze fuellen: alles ausser der letzten
        // Nachricht wird unterschlagen.
        let anzahl = MAX_SKIPPED_STORED.saturating_add(1);
        let mut unterschlagen = Vec::with_capacity(anzahl);
        for i in 0..anzahl {
            unterschlagen.push(a.encrypt(format!("weg{i}").as_bytes()).unwrap());
        }
        let letzte = unterschlagen.pop().unwrap();
        b.decrypt(&letzte.0, &letzte.1, rng.key()).unwrap();
        assert_eq!(
            b.skipped_len(),
            MAX_SKIPPED_STORED,
            "Vorbedingung: Vorrat muss voll sein"
        );

        // Eine weitere Luecke: n wird unterschlagen, n+1 kommt an.
        let _verloren = a.encrypt(b"verloren").unwrap();
        let (h, ct) = a.encrypt(b"muss ankommen").unwrap();

        assert_eq!(
            b.decrypt(&h, &ct, rng.key()).unwrap(),
            b"muss ankommen",
            "voller Vorrat darf die Session nicht dauerhaft blockieren"
        );
        assert!(
            b.skipped_len() <= MAX_SKIPPED_STORED,
            "Obergrenze muss auch bei Verdraengung halten: {}",
            b.skipped_len()
        );
    }

    #[test]
    fn randomisierter_verkehr_mit_verzoegerter_zustellung() {
        let (mut a, mut b, mut rng) = paar();
        let mut unterwegs: Vec<(Header, Vec<u8>, String)> = Vec::new();
        let mut zugestellt = 0usize;

        for i in 0..200u32 {
            let pt = format!("m{i}");
            let (h, ct) = a.encrypt(pt.as_bytes()).unwrap();
            unterwegs.push((h, ct, pt));

            if !unterwegs.is_empty() && rng.next() % 3 != 0 {
                let idx = (rng.next() as usize) % unterwegs.len();
                let (h, ct, pt) = unterwegs.remove(idx);
                assert_eq!(b.decrypt(&h, &ct, rng.key()).unwrap(), pt.as_bytes());
                zugestellt += 1;
            }
        }
        for (h, ct, pt) in unterwegs {
            assert_eq!(b.decrypt(&h, &ct, rng.key()).unwrap(), pt.as_bytes());
            zugestellt += 1;
        }
        assert_eq!(zugestellt, 200, "kein Verlust, keine Doppelzustellung");
        assert_eq!(b.skipped_len(), 0, "am Ende keine offenen Luecken");
    }

    #[test]
    fn header_ad_kodierung_ist_eindeutig() {
        let pk = DhPrivate::from_bytes([1u8; 32]).public();
        let a = Header {
            dh_pub: pk,
            pn: 1,
            n: 2,
        };
        let b = Header {
            dh_pub: pk,
            pn: 2,
            n: 1,
        };
        assert_ne!(a.encode_for_ad(), b.encode_for_ad());
        assert_ne!(a.associated_data(), b.associated_data());
        assert_eq!(a.encode_for_ad().len(), HEADER_AD_LEN);
    }

    /// Regression zu Befund K-1 des Security-Reviews: Ein Frame mit einem
    /// Punkt kleiner Ordnung als `dh_pub` darf die Session nicht toeten.
    #[test]
    fn eingeschleuster_low_order_frame_toetet_die_session_nicht() {
        let (mut a, mut b, mut rng) = paar();
        let (h1, ct1) = a.encrypt(b"echt-1").unwrap();
        b.decrypt(&h1, &ct1, rng.key()).unwrap();

        let boeser = Header {
            dh_pub: DhPublic::from_bytes([0u8; 32]), // Punkt kleiner Ordnung
            pn: 0,
            n: 0,
        };
        assert!(b.decrypt(&boeser, b"muell", rng.key()).is_err());

        // Die naechste echte Nachricht muss weiterhin ankommen.
        let (h2, ct2) = a.encrypt(b"echt-2").unwrap();
        assert_eq!(b.decrypt(&h2, &ct2, rng.key()).unwrap(), b"echt-2");
    }

    /// Regression zu Befund H-1: Ein wiederholt zugestellter Frame aus einer
    /// alten Kette (Mesh- und Tor-Zustellung derselben Nachricht, §13) darf
    /// den Zustand nicht beschaedigen.
    #[test]
    fn replay_ueber_die_ratchet_grenze_toetet_die_session_nicht() {
        let (mut a, mut b, mut rng) = paar();
        let (h_alt, ct_alt) = a.encrypt(b"alt").unwrap();
        b.decrypt(&h_alt, &ct_alt, rng.key()).unwrap();

        // Richtungswechsel: b sendet, a antwortet, b ratchet weiter.
        let (hb, ctb) = b.encrypt(b"antwort").unwrap();
        a.decrypt(&hb, &ctb, rng.key()).unwrap();
        let (h_neu, ct_neu) = a.encrypt(b"neu").unwrap();
        assert_eq!(b.decrypt(&h_neu, &ct_neu, rng.key()).unwrap(), b"neu");

        // Jetzt die alte Nachricht erneut zustellen.
        assert!(b.decrypt(&h_alt, &ct_alt, rng.key()).is_err());

        // Und danach muss der normale Betrieb weiterlaufen.
        let (h3, ct3) = a.encrypt(b"danach").unwrap();
        assert_eq!(b.decrypt(&h3, &ct3, rng.key()).unwrap(), b"danach");
    }

    /// Regression zu Befund T-2: ein ausgetauschter `dh_pub` im Header.
    #[test]
    fn fremder_dh_pub_im_header_toetet_die_session_nicht() {
        let (mut a, mut b, mut rng) = paar();
        let (h, ct) = a.encrypt(b"echt").unwrap();
        let gefaelscht = Header {
            dh_pub: rng.key().public(),
            pn: h.pn,
            n: h.n,
        };
        assert!(b.decrypt(&gefaelscht, &ct, rng.key()).is_err());
        assert_eq!(b.decrypt(&h, &ct, rng.key()).unwrap(), b"echt");
    }

    /// Ein manipuliertes Chiffrat darf einen bereits uebersprungenen
    /// Message Key nicht verbrauchen.
    #[test]
    fn manipulierter_frame_verbraucht_keinen_uebersprungenen_key() {
        let (mut a, mut b, mut rng) = paar();
        let m: Vec<_> = (0..3)
            .map(|i| a.encrypt(format!("m{i}").as_bytes()).unwrap())
            .collect();

        b.decrypt(&m[2].0, &m[2].1, rng.key()).unwrap();
        assert_eq!(b.skipped_len(), 2);

        let mut kaputt = m[0].1.clone();
        kaputt[0] ^= 0x01;
        assert!(b.decrypt(&m[0].0, &kaputt, rng.key()).is_err());
        assert_eq!(b.skipped_len(), 2, "Key darf nicht verbraucht sein");

        assert_eq!(b.decrypt(&m[0].0, &m[0].1, rng.key()).unwrap(), b"m0");
    }

    #[test]
    fn empfaenger_kann_vor_erstem_empfang_nicht_senden() {
        let sk = RootKey::from_bytes([1u8; 32]);
        let mut b = Ratchet::init_responder(sk, DhPrivate::from_bytes([2u8; 32]));
        assert_eq!(
            b.encrypt(b"zu frueh"),
            Err(CryptoError::RatchetStateInvalid)
        );
    }
}
