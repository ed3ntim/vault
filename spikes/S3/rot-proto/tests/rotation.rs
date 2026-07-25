//! Testfaelle zum Prototyp der erzwungenen Rotation.
//!
//! Geprueft werden die Invarianten aus `spec/protokoll-spec.md` §11 und
//! ADR-15. Die Zeitmodell-Tests arbeiten mit einem synthetischen Transport
//! (`SimTransport`) — dessen Verzoegerungen sind **frei gewaehlte
//! Rechenkonstanten und keine Messwerte.** Sie pruefen ausschliesslich, dass
//! die Auswertelogik richtig rechnet.

use std::time::Duration;

use rot_proto::desc::{self, Access, LocalTransport, ServiceIdentity};
use rot_proto::stats::{self, KRITERIUM_P95};
use rot_proto::{
    revoke, Compartment, RotError, RotationOrder, RotationTransport,
};
use tor_netdoc::doc::hsdesc::IntroPointDesc;

const IPTS: usize = 3;

fn aufbau(n_clients: usize, seed: u64) -> (Compartment, LocalTransport<rand::rngs::StdRng>, Vec<tor_hscrypto::pk::HsClientDescEncKeypair>) {
    let mut rng = desc::rng_from_seed(seed);
    let id = ServiceIdentity::generate(&mut rng).expect("identity");
    let kps = desc::make_clients(&mut rng, n_clients);
    let mut comp = Compartment::new(0);
    for (i, kp) in kps.iter().enumerate() {
        comp.authorized_clients.insert(i as u32, *kp.public().as_ref());
        comp.mesh_visibility.insert(i as u32, [i as u8; 32]);
        comp.sessions.insert(i as u32, vec![0x5A; 64]);
    }
    let mut tr = LocalTransport::new(id, desc::rng_from_seed(seed ^ 0xFFFF));
    comp.intro_points = tr.establish_intro_points(0, IPTS).expect("ipts");
    comp.revision_counter = 1;
    let clients: Vec<_> = comp.authorized_clients.values().copied().collect();
    tr.publish_descriptor(0, 1, &clients, &comp.intro_points)
        .expect("publish");
    comp.published = true;
    (comp, tr, kps)
}

#[test]
fn schritt_1_credential_entzogen() {
    let (mut comp, mut tr, _) = aufbau(4, 1);
    let vorher = comp.authorized_clients.len();
    revoke(&mut comp, &mut tr, 3, RotationOrder::TeardownFirst, IPTS).expect("revoke");
    assert_eq!(comp.authorized_clients.len(), vorher - 1);
    assert!(!comp.authorized_clients.contains_key(&3));
}

#[test]
fn schritt_2_epoche_waechst() {
    let (mut comp, mut tr, _) = aufbau(4, 2);
    assert_eq!(comp.intro_point_epoch, 0);
    revoke(&mut comp, &mut tr, 0, RotationOrder::TeardownFirst, IPTS).expect("revoke");
    assert_eq!(comp.intro_point_epoch, 1);
    revoke(&mut comp, &mut tr, 1, RotationOrder::TeardownFirst, IPTS).expect("revoke");
    assert_eq!(comp.intro_point_epoch, 2);
}

#[test]
fn schritt_3_intro_points_sind_neu() {
    let (mut comp, mut tr, _) = aufbau(4, 3);
    let alt: Vec<Vec<u8>> = comp.intro_points.iter().map(desc::ipt_fingerprint).collect();
    let out = revoke(&mut comp, &mut tr, 3, RotationOrder::TeardownFirst, IPTS).expect("revoke");
    let neu: Vec<Vec<u8>> = comp.intro_points.iter().map(desc::ipt_fingerprint).collect();
    assert_eq!(out.timeline.withdrawn, IPTS);
    assert_eq!(neu.len(), IPTS);
    for f in &neu {
        assert!(!alt.contains(f), "Intro-Point wurde nicht rotiert");
    }
}

#[test]
fn revozierter_kommt_an_neuen_descriptor_nicht_heran() {
    let (mut comp, mut tr, kps) = aufbau(4, 4);
    revoke(&mut comp, &mut tr, 3, RotationOrder::TeardownFirst, IPTS).expect("revoke");
    let d = tr.last_descriptor().expect("descriptor").clone();
    match desc::try_access(&tr.id, &d, Some(&kps[3])) {
        Access::Denied(_) => {}
        Access::Granted(_) => panic!("revozierter Kontakt hat Zugriff auf den neuen Descriptor"),
    }
    for kp in kps.iter().take(3) {
        match desc::try_access(&tr.id, &d, Some(kp)) {
            Access::Granted(ipts) => assert_eq!(ipts.len(), IPTS),
            Access::Denied(e) => panic!("verbliebener Kontakt abgewiesen: {e}"),
        }
    }
}

#[test]
fn alter_descriptor_bleibt_fuer_den_revozierten_lesbar() {
    // Der Kern des Problems: der Republish entzieht nichts, solange der
    // Revozierte den alten Descriptor im Cache hat.
    let (mut comp, mut tr, kps) = aufbau(4, 5);
    let alt = tr.published[0].clone();
    revoke(&mut comp, &mut tr, 3, RotationOrder::TeardownFirst, IPTS).expect("revoke");
    match desc::try_access(&tr.id, &alt, Some(&kps[3])) {
        Access::Granted(ipts) => assert_eq!(ipts.len(), IPTS),
        Access::Denied(e) => panic!("alter Descriptor unerwartet nicht lesbar: {e}"),
    }
}

#[test]
fn revision_counter_waechst() {
    let (mut comp, mut tr, _) = aufbau(4, 6);
    let vorher = comp.revision_counter;
    revoke(&mut comp, &mut tr, 3, RotationOrder::TeardownFirst, IPTS).expect("revoke");
    assert!(comp.revision_counter > vorher);
}

#[test]
fn schritt_4_und_5_mesh_und_session_weg() {
    let (mut comp, mut tr, _) = aufbau(4, 7);
    assert!(comp.mesh_visibility.contains_key(&2));
    assert!(comp.sessions.contains_key(&2));
    revoke(&mut comp, &mut tr, 2, RotationOrder::TeardownFirst, IPTS).expect("revoke");
    assert!(!comp.mesh_visibility.contains_key(&2));
    assert!(!comp.sessions.contains_key(&2));
}

#[test]
fn leerfall_wird_nicht_publiziert() {
    // ADR-16 Punkt 6 / S1-T8: Client-Auth mit 0 Clients erzeugt in Arti
    // Bug/BadApiUsage. Der Prototyp nimmt den Dienst stattdessen vom Netz.
    let (mut comp, mut tr, _) = aufbau(1, 8);
    let vorher = tr.published.len();
    revoke(&mut comp, &mut tr, 0, RotationOrder::TeardownFirst, IPTS).expect("revoke");
    assert_eq!(tr.published.len(), vorher, "es wurde trotzdem publiziert");
    assert!(tr.unpublished);
    assert!(!comp.published);
}

#[test]
fn unbekannter_kontakt_wird_abgewiesen() {
    let (mut comp, mut tr, _) = aufbau(2, 9);
    assert_eq!(
        revoke(&mut comp, &mut tr, 99, RotationOrder::TeardownFirst, IPTS).unwrap_err(),
        RotError::UnknownContact(99)
    );
}

#[test]
fn make_before_break_hat_keine_erreichbarkeitsluecke() {
    let (mut comp, mut tr, _) = aufbau(4, 10);
    let out = revoke(&mut comp, &mut tr, 3, RotationOrder::MakeBeforeBreak, IPTS).expect("revoke");
    assert_eq!(out.timeline.outage, Duration::ZERO);
}

#[test]
fn teardown_first_hat_eine_erreichbarkeitsluecke() {
    let (mut comp, mut tr, _) = aufbau(4, 11);
    let out = revoke(&mut comp, &mut tr, 3, RotationOrder::TeardownFirst, IPTS).expect("revoke");
    assert!(out.timeline.t_old_ipts_withdrawn <= out.timeline.t_descriptor_published);
    assert!(out.timeline.outage > Duration::ZERO);
}

// ---------------------------------------------------------------------------
// Auswertelogik gegen das Kriterium — mit SYNTHETISCHEN Verzoegerungen.
// ---------------------------------------------------------------------------

/// Transport mit frei gewaehlten Verzoegerungen. **Keine Messwerte.**
/// Dient nur dazu, die Auswertung gegen das 5-Minuten-Kriterium zu pruefen.
struct SimTransport {
    inner: LocalTransport<rand::rngs::StdRng>,
    withdraw: Duration,
    establish: Duration,
    publish: Duration,
}

impl RotationTransport for SimTransport {
    fn withdraw_intro_points(&mut self, e: u32) -> Result<usize, RotError> {
        std::thread::sleep(self.withdraw);
        self.inner.withdraw_intro_points(e)
    }
    fn establish_intro_points(&mut self, e: u32, n: usize) -> Result<Vec<IntroPointDesc>, RotError> {
        std::thread::sleep(self.establish);
        self.inner.establish_intro_points(e, n)
    }
    fn publish_descriptor(
        &mut self,
        e: u32,
        rev: u64,
        auth: &[tor_llcrypto::pk::curve25519::PublicKey],
        ipts: &[IntroPointDesc],
    ) -> Result<Vec<u8>, RotError> {
        std::thread::sleep(self.publish);
        self.inner.publish_descriptor(e, rev, auth, ipts)
    }
    fn unpublish(&mut self) -> Result<(), RotError> {
        self.inner.unpublish()
    }
}

#[test]
fn auswertung_rechnet_gegen_das_kriterium() {
    let (mut comp, inner, _) = aufbau(4, 12);
    let mut sim = SimTransport {
        inner,
        withdraw: Duration::from_millis(5),
        establish: Duration::from_millis(10),
        publish: Duration::from_millis(15),
    };
    let out = revoke(&mut comp, &mut sim, 3, RotationOrder::TeardownFirst, IPTS).expect("revoke");
    // Zugriffsverlust des Revozierten = Abriss der alten Intro-Points.
    assert!(out.timeline.t_old_ipts_withdrawn >= Duration::from_millis(5));
    // Wirksam (ADR-15) erst nach der Publikation.
    assert!(out.timeline.t_descriptor_published >= Duration::from_millis(30));
    // Erreichbarkeitsluecke = Publikation minus Abriss.
    assert!(out.timeline.outage >= Duration::from_millis(25));
    // Und die Bewertung gegen das Kriterium.
    let s = stats::summarize(vec![out.timeline.t_old_ipts_withdrawn]);
    assert!(s.p95 < KRITERIUM_P95);
    assert_eq!(stats::urteil(s.p95), "unter 300 s");
}

#[test]
fn auswertung_erkennt_ein_gerissenes_kriterium() {
    let werte = vec![
        Duration::from_secs(10),
        Duration::from_secs(20),
        Duration::from_secs(600),
    ];
    let s = stats::summarize(werte);
    assert_eq!(stats::urteil(s.p95), "300 s oder mehr — Kriterium gerissen");
}
