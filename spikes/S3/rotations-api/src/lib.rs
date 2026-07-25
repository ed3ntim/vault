//! Spike S3 — API-Oberflaeche fuer die erzwungene Intro-Point-Rotation.
//!
//! Frage: `spec/protokoll-spec.md` §11 Schritt 3 verlangt
//! `tor: rotate_intro_points(onion_c); republish_descriptor(onion_c)`.
//! ADR-15 legt fest, dass Vault das selbst erzwingt. Welche Hebel bietet die
//! oeffentliche API von arti 0.44.0 dafuer tatsaechlich?
//!
//! Jeder Hebel ist ein eigenes Cargo-Feature. Ob er existiert, entscheidet der
//! Compiler, nicht die Dokumentation.

/// **L1 — Clientliste aendern und den Dienst neu konfigurieren.**
///
/// Erwartung: uebersetzt. Das ist der Hebel, den `restricted_discovery`
/// anbietet. Er entfernt die Credential (Schritt 1 in §11) — er rotiert
/// ausdruecklich **keine** Intro-Points
/// (`tor-hsservice-0.44.0/src/config/restricted_discovery.rs:50-62`).
pub fn l1_reduce_client_list(
    svc: &tor_hsservice::RunningOnionService,
    verbleibende: Vec<(
        tor_hsservice::config::restricted_discovery::HsClientNickname,
        tor_hscrypto::pk::HsClientDescEncKey,
    )>,
    nickname: tor_hsservice::HsNickname,
) -> Result<(), String> {
    use tor_hsservice::config::OnionServiceConfigBuilder;
    use tor_hsservice::config::restricted_discovery::{
        RestrictedDiscoveryConfigBuilder, StaticKeyProviderBuilder,
    };

    let mut static_keys = StaticKeyProviderBuilder::default();
    for eintrag in verbleibende {
        static_keys.access().push(eintrag);
    }
    let mut rd = RestrictedDiscoveryConfigBuilder::default();
    rd.enabled(true);
    *rd.static_keys() = static_keys;

    let mut osc = OnionServiceConfigBuilder::default();
    osc.nickname(nickname);
    *osc.restricted_discovery() = rd;
    let cfg = osc.build().map_err(|e| e.to_string())?;

    svc.reconfigure(cfg, tor_config::Reconfigure::WarnOnFailures)
        .map_err(|e| e.to_string())
}

/// **L2 — Dienst anhalten.**
///
/// Erwartung: uebersetzt NICHT. `RunningOnionService::pause` ist in
/// `tor-hsservice-0.44.0/src/lib.rs:552-561` auskommentiert (TODO #1231).
#[cfg(feature = "probe-pause")]
pub fn l2_pause(svc: &tor_hsservice::RunningOnionService) {
    svc.pause();
}

/// **L3 — Intro-Points direkt rotieren.**
///
/// Erwartung: uebersetzt NICHT. Eine solche Methode existiert in der
/// oeffentlichen API nicht; die Rotation liegt allein beim `IptManager`
/// (`planned_retirement`, zufaellig aus `hs_intro_min/max_lifetime`).
#[cfg(feature = "probe-rotate")]
pub fn l3_rotate(svc: &tor_hsservice::RunningOnionService) {
    svc.rotate_intro_points();
}

/// **L4 — Dienst fallen lassen und neu starten.**
///
/// Erwartung: uebersetzt. Das Fallenlassen des letzten `Arc` beendet den
/// Dienst (`#[must_use = "a hidden service object will terminate the service
/// when dropped"]`, `lib.rs:141`). Ob dabei die Intro-Points wechseln, ist
/// eine andere Frage — siehe `ipt_mgr/persist.rs`.
#[cfg(feature = "probe-relaunch")]
pub fn l4_relaunch<R: tor_rtcompat::Runtime>(
    client: &arti_client::TorClient<R>,
    cfg: tor_hsservice::OnionServiceConfig,
    alt: std::sync::Arc<tor_hsservice::RunningOnionService>,
) -> Result<bool, arti_client::Error> {
    // Dienst beenden: letzten Arc fallen lassen.
    drop(alt);
    // Neu starten.
    Ok(client.launch_onion_service(cfg)?.is_some())
}

/// **Bestaetigung der Rotation (ADR-15 Punkt 3).**
///
/// Frage: kann Vault ueber die oeffentliche API ablesen, dass der Descriptor
/// der NEUEN Epoche publiziert ist und die ALTEN Intro-Points abgeraeumt sind?
/// Erwartung: uebersetzt NICHT — `OnionServiceStatus` liefert nur einen
/// groben Zustand (`State::{Bootstrapping, Running, ...}`) ohne
/// Revisionsnummer, ohne Epoche und ohne Intro-Point-Liste.
#[cfg(feature = "probe-confirm")]
pub fn probe_confirm(svc: &tor_hsservice::RunningOnionService) -> (u64, usize) {
    let st = svc.status();
    // Existiert eine Auskunft ueber den zuletzt publizierten Descriptor?
    let rev = st.published_revision_counter();
    // Existiert eine Auskunft ueber die aktuell etablierten Intro-Points?
    let ipts = st.intro_points().len();
    (rev, ipts)
}

/// Kontrolle: das, was `OnionServiceStatus` tatsaechlich hergibt.
/// Erwartung: uebersetzt (Teil des Default-Laufs).
pub fn status_oberflaeche(svc: &tor_hsservice::RunningOnionService) -> (bool, bool) {
    let st = svc.status();
    (st.state().is_fully_reachable(), st.current_problem().is_some())
}
