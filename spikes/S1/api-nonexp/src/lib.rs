//! Spike S1 — API-Oberflaechen-Test ohne `experimental-api`.
//!
//! Fragestellung aus spec/phase0-spikeplan.md §2 (S1):
//! "Unterstuetzt Arti Onion-Services mit v3 Client Authorization
//!  produktionsreif?"
//!
//! "Produktionsreif" heisst hier mindestens: ohne die von Arti selbst als
//! instabil markierten Features (`experimental-api`, `__is_experimental`)
//! nutzbar, weil diese ausdruecklich keine Semver-Zusagen tragen.
//!
//! Dieses Crate wird ohne `experimental-api` uebersetzt.

/// Service-Seite: Onion-Service mit Restricted Discovery (= v3 Client Auth)
/// konfigurieren. Erwartung: uebersetzt ohne `experimental-api`.
pub fn service_side_restricted_discovery(
    client_key: tor_hscrypto::pk::HsClientDescEncKey,
) -> Result<tor_hsservice::OnionServiceConfig, String> {
    use tor_hsservice::config::OnionServiceConfigBuilder;
    use tor_hsservice::config::restricted_discovery::{
        HsClientNickname, RestrictedDiscoveryConfigBuilder, StaticKeyProviderBuilder,
    };

    let mut static_keys = StaticKeyProviderBuilder::default();
    static_keys.access().push((
        "kontakt-1"
            .parse::<HsClientNickname>()
            .map_err(|e| e.to_string())?,
        client_key,
    ));

    let mut rd = RestrictedDiscoveryConfigBuilder::default();
    rd.enabled(true);
    *rd.static_keys() = static_keys;

    let mut osc = OnionServiceConfigBuilder::default();
    osc.nickname(
        "vault-kompartiment"
            .parse::<tor_hsservice::HsNickname>()
            .map_err(|e| e.to_string())?,
    );
    *osc.restricted_discovery() = rd;
    osc.build().map_err(|e| e.to_string())
}

/// Service-Seite: Start des Dienstes. Erwartung: `launch_onion_service` ist
/// nicht experimentell.
pub fn service_side_launch<R: tor_rtcompat::Runtime>(
    client: &arti_client::TorClient<R>,
    cfg: tor_hsservice::OnionServiceConfig,
) -> Result<bool, arti_client::Error> {
    Ok(client.launch_onion_service(cfg)?.is_some())
}

/// Client-Seite: Verwaltung des eigenen Client-Auth-Schluessels.
/// Erwartung: uebersetzt NICHT ohne `experimental-api`.
#[cfg(feature = "client-key-api")]
pub fn client_side_key_management<R: tor_rtcompat::Runtime>(
    client: &arti_client::TorClient<R>,
    hsid: tor_hscrypto::pk::HsId,
) -> Result<tor_hscrypto::pk::HsClientDescEncKey, arti_client::Error> {
    client.generate_service_discovery_key(tor_keymgr::KeystoreSelector::Primary, hsid)
}
