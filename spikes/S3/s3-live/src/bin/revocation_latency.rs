//! Spike S3 — Ende-zu-Ende-Messung der Revocation-Latenz.
//!
//! Kriterium (`spec/phase0-spikeplan.md` §3, S3):
//!   „Revocation -> Verbindungsverlust des Revozierten in < 5 min (p95);
//!    Intro-Point-Rotation greift"
//!
//! Gemessen wird NICHT die Dauer eines API-Aufrufs, sondern die Zeit vom
//! Revocation-Ausloeser bis zu dem Zeitpunkt, an dem der revozierte Client
//! **belegbar nicht mehr verbindet**.
//!
//! Messdefinition (bewusst streng):
//!   t_trigger      = Zeitpunkt, an dem Schritt 1 aus §11 ausgefuehrt wird
//!   t_verlust      = erster Sondierungszeitpunkt, ab dem der revozierte
//!                    Client `BESTAETIGUNG` aufeinanderfolgende Versuche
//!                    hintereinander scheitert
//!   Gegenprobe     = ein verbliebener Kontakt muss im selben Zeitraum
//!                    (wieder) verbinden koennen. Ohne diese Gegenprobe waere
//!                    ein Messwert wertlos: ein Dienst, der fuer alle tot ist,
//!                    hat niemanden revoziert.
//!   t_wiederkehr   = Zeitpunkt, ab dem der verbliebene Kontakt wieder
//!                    verbindet (Erreichbarkeitsluecke, Preis der Rotation)
//!
//! Varianten:
//!   A `reconfigure`  — nur die Clientliste verkleinern (Bibliotheks-Hebel L1)
//!   B `forced`       — von Vault erzwungene Rotation (ADR-15): Dienst
//!                      beenden, IPT-Zustand und IPT-Schluessel loeschen,
//!                      mit verkleinerter Clientliste neu starten
//!
//! Aufruf:
//!   revocation-latency <variante:a|b|ab> [BEOBACHTUNG_S] [SONDE_S] [BOOT_TIMEOUT_S]
//! Beispiel:
//!   revocation-latency ab 1800 15 600
//!
//! Es werden keine Onion-Adressen, Schluessel oder Kontakt-IDs geloggt
//! (`CLAUDE.md`).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use arti_client::{StreamPrefs, TorClient, TorClientConfig};
use futures::StreamExt;
use safelog::DisplayRedacted as _;
use tor_hscrypto::pk::{HsClientDescEncKeypair, HsClientDescEncSecretKey, HsId};
use tor_hsservice::config::restricted_discovery::{
    HsClientNickname, RestrictedDiscoveryConfigBuilder, StaticKeyProviderBuilder,
};
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::status::State;
use tor_hsservice::{HsNickname, OnionServiceConfig, RunningOnionService};
use tor_keymgr::KeystoreSelector;
use tor_llcrypto::pk::curve25519;
use tor_rtcompat::{PreferredRuntime, Runtime};

const SERVICE_PORT: u16 = 8080;
const NICKNAME: &str = "vault-s3";
/// Wie viele Fehlversuche hintereinander als „verbindet nicht mehr" gelten.
const BESTAETIGUNG: usize = 3;

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
    // Nur fuer den Spike: keine strengen Dateirechte erzwingen.
    b.storage().permissions().dangerously_trust_everyone();
    b.build().map_err(|e| anyhow!("config: {e}"))
}

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

/// Baut die Dienstkonfiguration mit genau den uebergebenen Kontakten.
fn service_config(clients: &[(String, curve25519::PublicKey)]) -> Result<OnionServiceConfig> {
    let mut static_keys = StaticKeyProviderBuilder::default();
    for (nick, pk) in clients {
        static_keys.access().push((
            nick.parse::<HsClientNickname>()
                .map_err(|e| anyhow!("client nickname: {e}"))?,
            (*pk).into(),
        ));
    }
    let mut rd = RestrictedDiscoveryConfigBuilder::default();
    rd.enabled(true);
    *rd.static_keys() = static_keys;

    let mut osc = OnionServiceConfigBuilder::default();
    osc.nickname(
        NICKNAME
            .parse::<HsNickname>()
            .map_err(|e| anyhow!("nickname: {e}"))?,
    );
    *osc.restricted_discovery() = rd;
    osc.build().map_err(|e| anyhow!("onion service config: {e}"))
}

async fn wait_running(svc: &Arc<RunningOnionService>, timeout: Duration) -> Result<Duration> {
    let t0 = Instant::now();
    let mut events = svc.status_events();
    loop {
        if svc.status().state() == State::Running {
            return Ok(t0.elapsed());
        }
        if t0.elapsed() > timeout {
            return Err(anyhow!(
                "Onion-Service nicht Running nach {:?} (Status {:?})",
                timeout,
                svc.status().state()
            ));
        }
        let _ = tokio::time::timeout(Duration::from_secs(5), events.next()).await;
    }
}

/// Ein Verbindungsversuch. `true` = verbunden.
async fn probe<R: Runtime>(client: &TorClient<R>, addr: &str, timeout: Duration) -> bool {
    let mut prefs = StreamPrefs::new();
    // Frische Isolation: verhindert, dass ein bereits offener Circuit das
    // Ergebnis faelscht. Gemessen werden soll der NEUE Zugriff.
    prefs.set_isolation(arti_client::IsolationToken::new());
    matches!(
        tokio::time::timeout(timeout, client.connect_with_prefs(addr, &prefs)).await,
        Ok(Ok(_))
    )
}

/// Loescht den persistenten Intro-Point-Zustand und die Intro-Point-Schluessel
/// des Dienstes.
///
/// Begruendung: `tor-hsservice-0.44.0/src/ipt_mgr/persist.rs:95-138` stellt
/// beim Neustart **dieselben** Intro-Point-Relays samt Schluesseln wieder her
/// (`IptExpectExistingKeys`) und ruft sofort `start_accepting`. Ein blosser
/// Neustart rotiert also nichts. Die Identitaet des Dienstes (KS_hs_id) bleibt
/// erhalten — die Onion-Adresse darf sich nicht aendern
/// (`spec/gesamtkonzept.md` §2.2: keine Neu-Verifikation).
///
/// ACHTUNG: Pfadannahmen ueber das Arti-Zustandsverzeichnis. Sie sind in
/// dieser Umgebung NICHT gegen einen laufenden Dienst geprueft worden
/// (der Bootstrap kam nicht zustande) und muessen beim ersten echten Lauf
/// verifiziert werden — die Funktion meldet, was sie tatsaechlich geloescht hat.
fn purge_intro_point_state(state_dir: &Path) -> Result<Vec<String>> {
    let mut removed = Vec::new();
    let kandidaten = [
        state_dir.join("hss").join(NICKNAME),
        state_dir.join("keystore").join("hss").join(NICKNAME).join("ipts"),
    ];
    for p in kandidaten {
        if p.exists() {
            // Der Zustandsordner enthaelt Replay-Logs und IPT-Records, keine
            // Identitaetsschluessel.
            std::fs::remove_dir_all(&p)
                .with_context(|| format!("loeschen von {}", p.display()))?;
            removed.push(p.display().to_string());
        }
    }
    Ok(removed)
}

struct Messung {
    variante: &'static str,
    t_verlust: Option<Duration>,
    t_wiederkehr: Option<Duration>,
    sonden: Vec<(u64, bool, bool)>, // (Sekunden seit Trigger, revoked ok, bleibt ok)
}

#[allow(clippy::too_many_arguments)]
async fn beobachte<R: Runtime>(
    variante: &'static str,
    revoked: &TorClient<R>,
    bleibt: &TorClient<R>,
    addr: &str,
    trigger: Instant,
    beobachtung: Duration,
    sonde: Duration,
    connect_timeout: Duration,
) -> Messung {
    let mut sonden = Vec::new();
    let mut fehlversuche = 0usize;
    let mut t_verlust = None;
    let mut t_wiederkehr = None;
    let mut erste_verlustsonde: Option<Duration> = None;

    while trigger.elapsed() < beobachtung {
        let seit = trigger.elapsed();
        let r_ok = probe(revoked, addr, connect_timeout).await;
        let b_ok = probe(bleibt, addr, connect_timeout).await;
        sonden.push((seit.as_secs(), r_ok, b_ok));
        println!(
            "     [{variante}] t+{:>5} s  revoziert: {}  verblieben: {}",
            seit.as_secs(),
            if r_ok { "VERBUNDEN" } else { "abgewiesen" },
            if b_ok { "verbunden " } else { "abgewiesen" }
        );

        if b_ok && t_wiederkehr.is_none() {
            t_wiederkehr = Some(seit);
        }
        if r_ok {
            fehlversuche = 0;
            erste_verlustsonde = None;
        } else {
            if erste_verlustsonde.is_none() {
                erste_verlustsonde = Some(seit);
            }
            fehlversuche += 1;
            if fehlversuche >= BESTAETIGUNG && t_verlust.is_none() {
                t_verlust = erste_verlustsonde;
                println!(
                    "     [{variante}] Verbindungsverlust bestaetigt ({BESTAETIGUNG} Fehlversuche in Folge), \
                     erster Fehlversuch bei t+{} s",
                    t_verlust.unwrap_or_default().as_secs()
                );
            }
        }
        if t_verlust.is_some() && t_wiederkehr.is_some() {
            break;
        }
        tokio::time::sleep(sonde).await;
    }

    Messung {
        variante,
        t_verlust,
        t_wiederkehr,
        sonden,
    }
}

fn bericht(m: &Messung) {
    println!();
    println!("== Variante {} ==", m.variante);
    println!("   Sonden: {}", m.sonden.len());
    match m.t_verlust {
        Some(d) => println!(
            "   t_verlust (Revozierter verbindet nicht mehr): {} s  -> Kriterium < 300 s: {}",
            d.as_secs(),
            if d < Duration::from_secs(300) {
                "erfuellt"
            } else {
                "GERISSEN"
            }
        ),
        None => println!(
            "   t_verlust: NICHT EINGETRETEN im Beobachtungsfenster \
             -> Kriterium GERISSEN oder Fenster zu kurz"
        ),
    }
    match m.t_wiederkehr {
        Some(d) => println!(
            "   t_wiederkehr (verbliebener Kontakt wieder erreichbar): {} s",
            d.as_secs()
        ),
        None => println!("   t_wiederkehr: NICHT eingetreten — Gegenprobe fehlt, Messwert ungueltig"),
    }
    if m.t_verlust.is_some() && m.t_wiederkehr.is_none() {
        println!("   WARNUNG: Der Dienst war fuer ALLE unerreichbar. Das ist keine Revocation,");
        println!("            sondern ein Ausfall. Der Wert oben darf nicht zitiert werden.");
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();

    let variante = std::env::args().nth(1).unwrap_or_else(|| "ab".into());
    let beobachtung = Duration::from_secs(
        std::env::args()
            .nth(2)
            .and_then(|s| s.parse().ok())
            .unwrap_or(1800),
    );
    let sonde = Duration::from_secs(
        std::env::args()
            .nth(3)
            .and_then(|s| s.parse().ok())
            .unwrap_or(15),
    );
    let boot_timeout = Duration::from_secs(
        std::env::args()
            .nth(4)
            .and_then(|s| s.parse().ok())
            .unwrap_or(600),
    );

    println!("# Spike S3 — Revocation-Latenz gegen das echte Tor-Netz");
    println!("# spec/phase0-spikeplan.md §3 (S3) · spec/protokoll-spec.md §11 · ADR-15");
    println!("# Plattform: {}", std::env::consts::OS);
    println!(
        "# Variante(n): {variante} · Beobachtung {} s · Sondenabstand {} s · Bootstrap-Timeout {} s",
        beobachtung.as_secs(),
        sonde.as_secs(),
        boot_timeout.as_secs()
    );
    println!("# Bestaetigung eines Verlusts: {BESTAETIGUNG} Fehlversuche in Folge");
    println!();

    let rt = PreferredRuntime::current()?;

    // ---------- Bootstrap Service ----------
    // Harter Abbruch statt `?`: gemessen am 2026-07-25 terminiert der Prozess
    // sonst nicht von selbst — das Fallenlassen eines halb gebooteten
    // TorClient haengt (siehe ergebnisse/T-live-versuch.txt, Versuch 3).
    let t0 = Instant::now();
    let svc_client = match tokio::time::timeout(
        boot_timeout,
        TorClient::with_runtime(rt.clone())
            .config(config_for("service")?)
            .create_bootstrapped(),
    )
    .await
    {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            println!("[B1] Bootstrap der Service-Seite gescheitert: {e}");
            std::process::exit(3);
        }
        Err(_) => {
            println!(
                "[B1] Bootstrap der Service-Seite nach {} s nicht abgeschlossen — Abbruch.",
                boot_timeout.as_secs()
            );
            println!("     Keine Messwerte. Dieser Lauf belegt nur die Umgebung.");
            std::process::exit(3);
        }
    };
    println!("[B1] Bootstrap Service-Seite: {} ms", t0.elapsed().as_millis());

    // ---------- Zwei Kontakte: A bleibt, B wird revoziert ----------
    let mut rng = rand::rng();
    let a_secret = curve25519::StaticSecret::random_from_rng(&mut rng);
    let b_secret = curve25519::StaticSecret::random_from_rng(&mut rng);
    let a_pk: curve25519::PublicKey = (&a_secret).into();
    let b_pk: curve25519::PublicKey = (&b_secret).into();

    let alle = vec![
        ("kontakt-a".to_string(), a_pk),
        ("kontakt-b".to_string(), b_pk),
    ];
    let nur_a = vec![("kontakt-a".to_string(), a_pk)];

    let (mut svc, rend) = svc_client
        .launch_onion_service(service_config(&alle)?)
        .context("launch_onion_service")?
        .ok_or_else(|| anyhow!("Onion-Service deaktiviert"))?;
    serve(Box::pin(rend));
    let onion: HsId = svc.onion_address().ok_or_else(|| anyhow!("keine Onion-Adresse"))?;
    println!("[B2] Onion-Service gestartet (Adresse wird nicht geloggt)");

    let d = wait_running(&svc, boot_timeout).await?;
    println!("[B3] Status Running nach {} ms", d.as_millis());

    // ---------- Clients ----------
    let client_a = tokio::time::timeout(
        boot_timeout,
        TorClient::with_runtime(rt.clone())
            .config(config_for("client-a")?)
            .create_bootstrapped(),
    )
    .await
    .map_err(|_| anyhow!("Bootstrap Kontakt A nicht abgeschlossen"))??;
    let client_b = tokio::time::timeout(
        boot_timeout,
        TorClient::with_runtime(rt.clone())
            .config(config_for("client-b")?)
            .create_bootstrapped(),
    )
    .await
    .map_err(|_| anyhow!("Bootstrap Kontakt B nicht abgeschlossen"))??;

    let _ = client_a.insert_service_discovery_key(
        KeystoreSelector::Primary,
        onion,
        HsClientDescEncSecretKey::from(a_secret.clone()),
    )?;
    let _ = client_b.insert_service_discovery_key(
        KeystoreSelector::Primary,
        onion,
        HsClientDescEncSecretKey::from(b_secret.clone()),
    )?;
    let _ = HsClientDescEncKeypair::from_secret_key(HsClientDescEncSecretKey::from(b_secret));

    let addr = format!("{}:{}", onion.display_unredacted(), SERVICE_PORT);
    let connect_timeout = Duration::from_secs(60);

    // ---------- Kontrolle vor der Revocation ----------
    let a_ok = probe(&client_a, &addr, connect_timeout).await;
    let b_ok = probe(&client_b, &addr, connect_timeout).await;
    println!(
        "[B4] Kontrolle vor Revocation — A: {}  B: {}",
        if a_ok { "verbunden" } else { "abgewiesen" },
        if b_ok { "verbunden" } else { "abgewiesen" }
    );
    if !(a_ok && b_ok) {
        return Err(anyhow!(
            "Ausgangslage nicht hergestellt (beide Kontakte muessen vorher verbinden). \
             Ohne diese Kontrolle ist jeder spaetere Messwert wertlos."
        ));
    }

    let (state_dir, _) = workdir("service")?;

    // ---------- Variante A: nur reconfigure ----------
    if variante.contains('a') {
        println!();
        println!("[A] Revocation nur ueber reconfigure (Bibliotheks-Hebel L1)");
        let trigger = Instant::now();
        svc.reconfigure(service_config(&nur_a)?, tor_config::Reconfigure::WarnOnFailures)
            .map_err(|e| anyhow!("reconfigure: {e}"))?;
        println!("     reconfigure zurueck nach {} ms", trigger.elapsed().as_millis());
        let m = beobachte(
            "A/reconfigure",
            &client_b,
            &client_a,
            &addr,
            trigger,
            beobachtung,
            sonde,
            connect_timeout,
        )
        .await;
        bericht(&m);
    }

    // ---------- Variante B: erzwungene Rotation ----------
    if variante.contains('b') {
        println!();
        println!("[B] Von Vault erzwungene Rotation (ADR-15)");
        let trigger = Instant::now();
        // 1. Dienst beenden (letzten Arc fallen lassen).
        drop(svc);
        println!("     Dienst beendet nach {} ms", trigger.elapsed().as_millis());
        // 2. IPT-Zustand und IPT-Schluessel loeschen — sonst stellt Arti
        //    dieselben Intro-Points wieder her (ipt_mgr/persist.rs).
        let removed = purge_intro_point_state(&state_dir)?;
        println!(
            "     geloeschter Zustand: {} Eintraege nach {} ms",
            removed.len(),
            trigger.elapsed().as_millis()
        );
        for r in &removed {
            println!("       - {r}");
        }
        // 3. Mit verkleinerter Clientliste neu starten.
        let (svc2, rend2) = svc_client
            .launch_onion_service(service_config(&nur_a)?)
            .context("relaunch")?
            .ok_or_else(|| anyhow!("Onion-Service deaktiviert"))?;
        serve(Box::pin(rend2));
        svc = svc2;
        println!("     Neustart ausgeloest nach {} ms", trigger.elapsed().as_millis());

        let m = beobachte(
            "B/forced",
            &client_b,
            &client_a,
            &addr,
            trigger,
            beobachtung,
            sonde,
            connect_timeout,
        )
        .await;
        bericht(&m);

        match wait_running(&svc, boot_timeout).await {
            Ok(d) => println!("   Dienst nach Rotation wieder Running nach {} ms", d.as_millis()),
            Err(e) => println!("   Dienst nach Rotation nicht Running: {e}"),
        }
    }

    println!();
    println!("== Lauf beendet ==");
    Ok(())
}
