//! Spike S1 — Ende-zu-Ende-Messung gegen das echte Tor-Netz.
//!
//! Deckt die Methodenschritte 1-3 und 5 aus spec/phase0-spikeplan.md §2 (S1) ab:
//!   1. Arti bauen, Onion-Service mit `authorized_clients` aufsetzen
//!   2. autorisierter Client verbindet / nicht-autorisierter Client scheitert
//!   3. Descriptor-Abruf durch Dritte muss fehlschlagen
//!   5. Start- und Verbindungszeiten messen
//!
//! Gemessene Groessen:
//!   M1  Bootstrap-Dauer des Arti-Clients (Service-Seite)
//!   M2  Zeit von `launch_onion_service` bis Status == Running
//!   M3  Verbindungsaufbau autorisierter Client -> Onion (N Laeufe, p50/p95)
//!   M4  Verbindungsversuche nicht-autorisierter Client (muessen scheitern)
//!
//! Aufruf: bootstrap-timing [ANZAHL_CONNECT_LAEUFE] [TIMEOUT_SEKUNDEN]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use arti_client::{StreamPrefs, TorClient, TorClientConfig};
use futures::StreamExt;
use safelog::DisplayRedacted as _;
use tor_hscrypto::pk::{HsClientDescEncKeypair, HsClientDescEncSecretKey};
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::config::restricted_discovery::{
    HsClientNickname, RestrictedDiscoveryConfigBuilder, StaticKeyProviderBuilder,
};
use tor_hsservice::status::State;
use tor_hsservice::{HsNickname, RunningOnionService};
use tor_llcrypto::pk::curve25519;
use tor_keymgr::KeystoreSelector;
use tor_rtcompat::PreferredRuntime;

const SERVICE_PORT: u16 = 8080;

fn quantile(sorted_ms: &[u128], q: f64) -> u128 {
    if sorted_ms.is_empty() {
        return 0;
    }
    let idx = ((sorted_ms.len() as f64 - 1.0) * q).round() as usize;
    sorted_ms[idx.min(sorted_ms.len() - 1)]
}

fn workdir(name: &str) -> Result<(PathBuf, PathBuf)> {
    let base = std::env::current_dir()?.join("run").join(name);
    let state = base.join("state");
    let cache = base.join("cache");
    std::fs::create_dir_all(&state)?;
    std::fs::create_dir_all(&cache)?;
    Ok((state, cache))
}

fn config_for(name: &str) -> Result<TorClientConfig> {
    let (state, cache) = workdir(name)?;
    let mut b = TorClientConfig::builder();
    b.storage()
        .state_dir(tor_config_path::CfgPath::new_literal(state));
    b.storage()
        .cache_dir(tor_config_path::CfgPath::new_literal(cache));
    // Damit der Spike auch ohne restriktive Dateirechte laeuft (nur Spike!).
    b.storage().permissions().dangerously_trust_everyone();
    b.build().map_err(|e| anyhow!("config: {e}"))
}

/// Beantwortet eingehende Rendezvous-Anfragen mit einem Echo-Dienst.
fn serve(rend: impl futures::Stream<Item = tor_hsservice::RendRequest> + Send + Unpin + 'static) {
    use futures::AsyncReadExt;
    use futures::AsyncWriteExt;
    tokio::spawn(async move {
        let mut streams = tor_hsservice::handle_rend_requests(rend);
        while let Some(req) = streams.next().await {
            tokio::spawn(async move {
                let Ok(mut s) = req
                    .accept(tor_cell::relaycell::msg::Connected::new_empty())
                    .await
                else {
                    return;
                };
                let mut buf = [0u8; 32];
                if let Ok(n) = s.read(&mut buf).await {
                    let _ = s.write_all(&buf[..n]).await;
                    let _ = s.flush().await;
                }
            });
        }
    });
}

async fn wait_running(svc: &Arc<RunningOnionService>, timeout: Duration) -> Result<Duration> {
    let t0 = Instant::now();
    let mut events = svc.status_events();
    loop {
        let st = svc.status();
        if st.state() == State::Running {
            return Ok(t0.elapsed());
        }
        if t0.elapsed() > timeout {
            return Err(anyhow!(
                "Onion-Service nicht Running nach {:?} (Status: {:?})",
                timeout,
                st.state()
            ));
        }
        let _ = tokio::time::timeout(Duration::from_secs(5), events.next()).await;
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();

    let runs: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    let timeout_s: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);
    let timeout = Duration::from_secs(timeout_s);

    println!("# Spike S1 — Arti 0.44.0 Onion-Service mit Client-Auth gegen das echte Tor-Netz");
    println!("# Plattform: {}", std::env::consts::OS);
    println!("# Connect-Laeufe: {runs}, Timeout je Phase: {timeout_s} s");
    println!();

    let rt = PreferredRuntime::current()?;

    // ---------- M1: Bootstrap der Service-Seite ----------
    let t0 = Instant::now();
    let svc_client = TorClient::with_runtime(rt.clone())
        .config(config_for("service")?)
        .create_bootstrapped()
        .await
        .context("Bootstrap Service-Client")?;
    let m1 = t0.elapsed();
    println!("[M1] Arti-Bootstrap (Service-Seite): {} ms", m1.as_millis());

    // ---------- Onion-Service mit Client-Auth ----------
    let mut rng = rand::rng();
    // Das Client-Auth-Geheimnis wird hier selbst erzeugt, damit derselbe
    // Schluessel sowohl in die Service-Konfiguration (oeffentlicher Teil) als
    // auch in den Keystore des Clients (geheimer Teil) eingebracht werden kann.
    let client_secret = curve25519::StaticSecret::random_from_rng(&mut rng);
    let client_kp = HsClientDescEncKeypair::from_secret_key(HsClientDescEncSecretKey::from(
        client_secret.clone(),
    ));
    let client_pk = client_kp.public().clone();

    let mut static_keys = StaticKeyProviderBuilder::default();
    static_keys.access().push((
        "vault-kontakt-1"
            .parse::<HsClientNickname>()
            .map_err(|e| anyhow!("nickname: {e}"))?,
        client_pk.clone(),
    ));

    let mut rd = RestrictedDiscoveryConfigBuilder::default();
    rd.enabled(true);
    *rd.static_keys() = static_keys;

    let mut osc = OnionServiceConfigBuilder::default();
    osc.nickname(
        "vault-spike"
            .parse::<HsNickname>()
            .map_err(|e| anyhow!("nickname: {e}"))?,
    );
    *osc.restricted_discovery() = rd;
    let osc = osc
        .build()
        .map_err(|e| anyhow!("onion service config: {e}"))?;

    let t0 = Instant::now();
    let (svc, rend) = svc_client
        .launch_onion_service(osc)
        .context("launch_onion_service")?
        .ok_or_else(|| anyhow!("Onion-Service deaktiviert"))?;
    serve(Box::pin(rend));

    let onion = svc
        .onion_address()
        .ok_or_else(|| anyhow!("keine Onion-Adresse"))?;
    println!("[--] Onion-Service gestartet (Adresse wird nicht geloggt, siehe CLAUDE.md)");

    let m2 = wait_running(&svc, timeout).await;
    match &m2 {
        Ok(d) => println!(
            "[M2] launch_onion_service -> Status Running: {} ms (Launch-Aufruf selbst {} ms)",
            d.as_millis(),
            t0.elapsed().as_millis()
        ),
        Err(e) => println!("[M2] Onion-Service nicht Running: {e}"),
    }

    // ---------- autorisierter Client ----------
    let t0 = Instant::now();
    let auth_client = TorClient::with_runtime(rt.clone())
        .config(config_for("client-auth")?)
        .create_bootstrapped()
        .await
        .context("Bootstrap autorisierter Client")?;
    println!(
        "[M1b] Arti-Bootstrap (autorisierter Client): {} ms",
        t0.elapsed().as_millis()
    );

    // Client-Auth-Schluessel in den Keystore des Clients einbringen.
    // Achtung: diese API ist in arti-client 0.44.0 hinter `experimental-api`.
    let inserted = auth_client.insert_service_discovery_key(
        KeystoreSelector::Primary,
        onion,
        HsClientDescEncSecretKey::from(client_secret.clone()),
    )?;
    println!(
        "[--] Client-Auth-Key im Client-Keystore hinterlegt (passt zum Service-Key: {})",
        inserted == client_pk
    );

    let addr = format!("{}:{}", onion.display_unredacted(), SERVICE_PORT);

    // ---------- M3: Verbindungsaufbau autorisierter Client ----------
    let mut ok_ms: Vec<u128> = Vec::new();
    let mut fails = 0usize;
    for i in 0..runs {
        let mut prefs = StreamPrefs::new();
        prefs.set_isolation(arti_client::IsolationToken::new());
        let t = Instant::now();
        let res =
            tokio::time::timeout(timeout, auth_client.connect_with_prefs(&addr, &prefs)).await;
        match res {
            Ok(Ok(_stream)) => {
                let ms = t.elapsed().as_millis();
                ok_ms.push(ms);
                println!("     Lauf {:>2}: verbunden nach {ms} ms", i + 1);
            }
            Ok(Err(e)) => {
                fails += 1;
                println!(
                    "     Lauf {:>2}: FEHLER nach {} ms: {e}",
                    i + 1,
                    t.elapsed().as_millis()
                );
            }
            Err(_) => {
                fails += 1;
                println!(
                    "     Lauf {:>2}: TIMEOUT nach {} ms",
                    i + 1,
                    t.elapsed().as_millis()
                );
            }
        }
    }
    ok_ms.sort_unstable();
    println!();
    println!("[M3] autorisierter Client -> Onion-Service");
    println!(
        "     Laeufe: {runs}   erfolgreich: {}   gescheitert: {fails}",
        ok_ms.len()
    );
    if !ok_ms.is_empty() {
        println!(
            "     min {} ms | p50 {} ms | p95 {} ms | max {} ms",
            ok_ms[0],
            quantile(&ok_ms, 0.50),
            quantile(&ok_ms, 0.95),
            ok_ms[ok_ms.len() - 1]
        );
        println!(
            "     Kriterium Spec: p50 < 20000 ms -> {} | p95 < 60000 ms -> {}",
            if quantile(&ok_ms, 0.50) < 20_000 {
                "PASS"
            } else {
                "FAIL"
            },
            if quantile(&ok_ms, 0.95) < 60_000 {
                "PASS"
            } else {
                "FAIL"
            }
        );
    }
    println!();

    // ---------- M4: nicht-autorisierter Client ----------
    let noauth_client = TorClient::with_runtime(rt.clone())
        .config(config_for("client-noauth")?)
        .create_bootstrapped()
        .await
        .context("Bootstrap nicht-autorisierter Client")?;

    let mut denied = 0usize;
    let mut leaked = 0usize;
    let noauth_runs = runs.clamp(3, 5);
    for i in 0..noauth_runs {
        let mut prefs = StreamPrefs::new();
        prefs.set_isolation(arti_client::IsolationToken::new());
        let t = Instant::now();
        let res =
            tokio::time::timeout(timeout, noauth_client.connect_with_prefs(&addr, &prefs)).await;
        match res {
            Ok(Ok(_)) => {
                leaked += 1;
                println!("     Lauf {:>2}: VERBUNDEN — Client-Auth wirkungslos!", i + 1);
            }
            Ok(Err(e)) => {
                denied += 1;
                println!(
                    "     Lauf {:>2}: abgewiesen nach {} ms: {e}",
                    i + 1,
                    t.elapsed().as_millis()
                );
            }
            Err(_) => {
                denied += 1;
                println!(
                    "     Lauf {:>2}: abgewiesen (Timeout) nach {} ms",
                    i + 1,
                    t.elapsed().as_millis()
                );
            }
        }
    }
    println!();
    println!("[M4] nicht-autorisierter Client (kein Client-Auth-Key im Keystore)");
    println!("     Versuche: {noauth_runs}   abgewiesen: {denied}   durchgekommen: {leaked}");
    println!(
        "     Kriterium Spec (100 % Fehlschlag): {}",
        if leaked == 0 { "PASS" } else { "FAIL" }
    );

    println!();
    println!("== Lauf beendet ==");
    Ok(())
}
