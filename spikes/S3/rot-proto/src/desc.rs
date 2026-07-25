//! Descriptor-Werkzeug fuer S3.
//!
//! Baut v3-Onion-Descriptors mit Restricted Discovery ueber denselben
//! Bibliothekspfad, den `tor-hsservice` beim Publizieren nimmt
//! (`tor-hsservice-0.44.0/src/publish/descriptor.rs` -> `HsDescBuilder`).
//! Kein Netzverkehr.
//!
//! Abgeleitet vom Messprogramm aus `spikes/S1/desc-auth`.

use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};

use rand::SeedableRng;
use tor_checkable::{SelfSigned, Timebound};
use tor_hscrypto::pk::{HsClientDescEncKeypair, HsIdKeypair};
use tor_hscrypto::time::TimePeriod;
use tor_linkspec::LinkSpec;
use tor_llcrypto::pk::{curve25519, ed25519};
use tor_netdoc::NetdocBuilder;
use tor_netdoc::doc::hsdesc::{HsDesc, HsDescBuilder, IntroPointDesc, create_desc_sign_key_cert};

use crate::{RotError, RotationTransport};

/// Lebensdauer, die `tor-hsservice 0.44.0` in den Descriptor schreibt.
/// Quelle: `tor-hsservice-0.44.0/src/ipt_mgr.rs:27` (`IPT_PUBLISH_UNCERTAIN`)
/// bzw. `:29` (`IPT_PUBLISH_CERTAIN`) = 3 h; eingesetzt in
/// `publish/descriptor.rs:136` als `.lifetime(ipt_set.lifetime / 60)`.
pub const ARTI_DESCRIPTOR_LIFETIME_MINS: u16 = 180;

/// Dienst-Identitaet und Zeitperiode. Bleibt ueber die Rotation gleich —
/// die Onion-Adresse aendert sich bei einer Revocation ausdruecklich nicht
/// (`spec/gesamtkonzept.md` §2.2: „keine Neu-Verifikation noetig").
pub struct ServiceIdentity {
    pub blinded_id: tor_hscrypto::pk::HsBlindIdKeypair,
    pub subcredential: tor_hscrypto::Subcredential,
    pub hs_desc_sign: ed25519::Keypair,
    pub expiry: SystemTime,
    pub now: SystemTime,
}

pub fn rng_from_seed(seed: u64) -> rand::rngs::StdRng {
    rand::rngs::StdRng::seed_from_u64(seed)
}

fn curve25519_pk<R: rand::Rng + rand::CryptoRng>(rng: &mut R) -> curve25519::PublicKey {
    let sk = curve25519::EphemeralSecret::random_from_rng(rng);
    (&sk).into()
}

impl ServiceIdentity {
    pub fn generate<R: rand::Rng + rand::CryptoRng>(rng: &mut R) -> Result<Self, RotError> {
        let now = SystemTime::now();
        let hs_id = ed25519::Keypair::generate(rng);
        let hs_desc_sign = ed25519::Keypair::generate(rng);

        let period = TimePeriod::new(
            Duration::from_secs(24 * 3600),
            now,
            Duration::from_secs(12 * 3600),
        )
        .map_err(|e| RotError::Descriptor(format!("time period: {e}")))?;

        let (_, blinded_id, subcredential) =
            HsIdKeypair::from(ed25519::ExpandedKeypair::from(&hs_id))
                .compute_blinded_key(period)
                .map_err(|e| RotError::Descriptor(format!("blinded key: {e}")))?;

        Ok(Self {
            blinded_id,
            subcredential,
            hs_desc_sign,
            expiry: now + Duration::from_secs(3600),
            now,
        })
    }
}

/// Erzeugt einen frischen Satz Introduction Points fuer eine Epoche.
///
/// Jeder Intro-Point bekommt frische `KP_ntor`, `KP_hs_ipt_sid` und
/// `KP_hss_ntor`. Genau das ist die Rotation: die Schluessel, die ein
/// revozierter Kontakt aus seinem alten Descriptor kennt, gelten nicht mehr.
pub fn fresh_intro_points<R: rand::Rng + rand::CryptoRng>(
    rng: &mut R,
    epoch: u32,
    n: usize,
) -> Result<Vec<IntroPointDesc>, RotError> {
    (0..n)
        .map(|i| {
            let port = 9000u16
                .wrapping_add((epoch as u16).wrapping_mul(16))
                .wrapping_add(i as u16);
            let ls = LinkSpec::OrPort(Ipv4Addr::new(127, 0, 0, 1).into(), port)
                .encode()
                .map_err(|e| RotError::Descriptor(format!("linkspec: {e}")))?;
            IntroPointDesc::builder()
                .link_specifiers(vec![ls])
                .ipt_kp_ntor(curve25519_pk(rng))
                .kp_hs_ipt_sid(ed25519::Keypair::generate(rng).verifying_key().into())
                .kp_hss_ntor(curve25519_pk(rng).into())
                .build()
                .map_err(|e| RotError::Descriptor(format!("intro point: {e}")))
        })
        .collect()
}

/// Baut und signiert einen Descriptor.
/// `auth_clients = None` schaltet Client-Auth ab (nur fuer Kontrollfaelle).
pub fn build_descriptor<R: rand::Rng + rand::CryptoRng>(
    id: &ServiceIdentity,
    intro_points: &[IntroPointDesc],
    auth_clients: Option<&[curve25519::PublicKey]>,
    revision_counter: u64,
    rng: &mut R,
) -> Result<String, RotError> {
    let cert = create_desc_sign_key_cert(&id.hs_desc_sign.verifying_key(), &id.blinded_id, id.expiry)
        .map_err(|e| RotError::Descriptor(format!("sign cert: {e}")))?;
    let blinded_pk = (&id.blinded_id).into();
    HsDescBuilder::default()
        .blinded_id(&blinded_pk)
        .hs_desc_sign(&id.hs_desc_sign)
        .hs_desc_sign_cert(cert)
        .create2_formats(&[tor_cell::chancell::msg::HandshakeType::NTOR])
        .auth_required(None)
        .is_single_onion_service(false)
        .intro_points(intro_points)
        .intro_auth_key_cert_expiry(id.expiry)
        .intro_enc_key_cert_expiry(id.expiry)
        .lifetime(ARTI_DESCRIPTOR_LIFETIME_MINS.into())
        .revision_counter(revision_counter.into())
        .subcredential(id.subcredential)
        .auth_clients(auth_clients)
        .build_sign(rng)
        .map_err(|e| RotError::Descriptor(format!("build_sign: {e}")))
}

/// Fingerabdruck eines Intro-Points aus Sicht eines Clients:
/// die Schluessel, mit denen er den Dienst dort ansprechen wuerde.
pub fn ipt_fingerprint(ipt: &IntroPointDesc) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(ipt.ipt_ntor_key().as_bytes());
    v.extend_from_slice(ipt.ipt_sid_key().as_ref().as_bytes());
    v.extend_from_slice(ipt.svc_ntor_key().as_ref().as_bytes());
    v
}

/// Ergebnis eines Abrufversuchs durch einen Client.
pub enum Access {
    /// Zugriff gelungen; der Client kennt jetzt diese Intro-Point-Fingerabdruecke.
    Granted(Vec<Vec<u8>>),
    /// Zugriff verweigert (Grund).
    Denied(String),
}

/// Versucht, einen Descriptor als Client zu lesen.
/// `key = None` entspricht einem HSDir oder netzweiten Scanner.
pub fn try_access(
    id: &ServiceIdentity,
    encoded: &str,
    key: Option<&HsClientDescEncKeypair>,
) -> Access {
    let blinded_id: tor_hscrypto::pk::HsBlindId =
        ed25519::Ed25519Identity::from(*id.blinded_id.as_ref().public()).into();

    let parsed = match HsDesc::parse(encoded, &blinded_id) {
        Ok(p) => p,
        Err(e) => return Access::Denied(format!("parse: {e}")),
    };
    let checked = match parsed.check_signature() {
        Ok(c) => c,
        Err(e) => return Access::Denied(format!("outer signature: {e}")),
    };
    let timed = match checked.check_valid_at(&id.now) {
        Ok(t) => t,
        Err(e) => return Access::Denied(format!("outer timeliness: {e}")),
    };
    let inner = match timed.decrypt(&id.subcredential, key) {
        Ok(d) => d,
        Err(e) => return Access::Denied(format!("decrypt: {e}")),
    };
    let inner = match inner.check_valid_at(&id.now) {
        Ok(d) => d,
        Err(e) => return Access::Denied(format!("inner timeliness: {e}")),
    };
    let inner = match inner.check_signature() {
        Ok(d) => d,
        Err(e) => return Access::Denied(format!("inner signature: {e}")),
    };
    Access::Granted(inner.intro_points().iter().map(ipt_fingerprint).collect())
}

// ---------------------------------------------------------------------------
// LocalTransport — fuehrt die Rotation echt aus, aber ohne Netz.
// ---------------------------------------------------------------------------

/// Transport, der alle kryptografischen Arbeiten der Rotation echt ausfuehrt
/// (frische Intro-Point-Schluessel, Descriptor bauen und signieren), aber
/// keinerlei Netzverkehr erzeugt.
///
/// Damit ist der **lokale Anteil** der Revocation messbar. Die Netzanteile
/// (Circuit-Abriss, ESTABLISH_INTRO, HSDir-Upload) sind hier per Definition
/// null und im Bericht als nicht gemessen ausgewiesen.
pub struct LocalTransport<R: rand::Rng + rand::CryptoRng> {
    pub id: ServiceIdentity,
    pub rng: R,
    /// Alle jemals veroeffentlichten Descriptors, in Reihenfolge.
    pub published: Vec<String>,
    /// Fingerabdruecke der zuletzt etablierten Intro-Points.
    pub live_ipts: Vec<Vec<u8>>,
    /// Zaehler abgerissener Intro-Points.
    pub withdrawn_total: usize,
    /// Wurde `unpublish` aufgerufen?
    pub unpublished: bool,
}

impl<R: rand::Rng + rand::CryptoRng> LocalTransport<R> {
    pub fn new(id: ServiceIdentity, rng: R) -> Self {
        Self {
            id,
            rng,
            published: Vec::new(),
            live_ipts: Vec::new(),
            withdrawn_total: 0,
            unpublished: false,
        }
    }

    pub fn last_descriptor(&self) -> Option<&String> {
        self.published.last()
    }
}

impl<R: rand::Rng + rand::CryptoRng> RotationTransport for LocalTransport<R> {
    fn withdraw_intro_points(&mut self, _epoch: u32) -> Result<usize, RotError> {
        // Im echten Stack: IptEstablisher fallen lassen -> Circuit-DESTROY zum
        // Intro-Point -> der Relay vergisst die Registrierung.
        // Hier: die alten Fingerabdruecke gelten nicht mehr.
        let n = self.live_ipts.len();
        self.live_ipts.clear();
        self.withdrawn_total += n;
        Ok(n)
    }

    fn establish_intro_points(
        &mut self,
        epoch: u32,
        n: usize,
    ) -> Result<Vec<IntroPointDesc>, RotError> {
        let ipts = fresh_intro_points(&mut self.rng, epoch, n)?;
        self.live_ipts = ipts.iter().map(ipt_fingerprint).collect();
        Ok(ipts)
    }

    fn publish_descriptor(
        &mut self,
        _epoch: u32,
        revision_counter: u64,
        authorized: &[curve25519::PublicKey],
        intro_points: &[IntroPointDesc],
    ) -> Result<Vec<u8>, RotError> {
        let d = build_descriptor(
            &self.id,
            intro_points,
            Some(authorized),
            revision_counter,
            &mut self.rng,
        )?;
        let bytes = d.as_bytes().to_vec();
        self.published.push(d);
        Ok(bytes)
    }

    fn unpublish(&mut self) -> Result<(), RotError> {
        self.unpublished = true;
        Ok(())
    }
}

/// Erzeugt `n` Client-Auth-Schluesselpaare (`KP_hsc_desc_enc`).
pub fn make_clients<R: rand::Rng + rand::CryptoRng>(
    rng: &mut R,
    n: usize,
) -> Vec<HsClientDescEncKeypair> {
    (0..n).map(|_| HsClientDescEncKeypair::generate(rng)).collect()
}
