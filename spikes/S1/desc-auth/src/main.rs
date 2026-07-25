//! Spike S1 — Offline-Nachweis fuer Erfolgskriterium 3:
//! "Nicht-autorisierter Descriptor-Abruf schlaegt in 100 % der Versuche fehl"
//! (spec/phase0-spikeplan.md §2, S1).
//!
//! Aufbau (entspricht dem Pfad, den `tor-hsservice` beim Publizieren nimmt —
//! `tor_hsservice::publish::descriptor` ruft denselben `HsDescBuilder` auf):
//!
//!  1. Service-Identitaet (Ed25519) erzeugen, fuer eine Zeitperiode blinden
//!     -> HsBlindIdKeypair + Subcredential (rend-spec v3 2.5).
//!  2. N autorisierte Client-Keys (KP_hsc_desc_enc, x25519) erzeugen.
//!  3. Descriptor mit `auth_clients = Some(...)` bauen und signieren
//!     (= Restricted Discovery / v3 Client Authorization aktiv).
//!  4. Entschluesselungsversuche:
//!       a) jeder autorisierte Client  -> MUSS gelingen
//!       b) M nicht-autorisierte Keys  -> MUSS fehlschlagen
//!       c) ohne Key ("HSDir/Scanner") -> MUSS fehlschlagen
//!  5. Kontrolle: derselbe Descriptor ohne Client-Auth ist ohne Key lesbar
//!     (zeigt, dass der Fehlschlag in 4c an der Client-Auth liegt und nicht
//!     an einem kaputten Testaufbau).
//!  6. Descriptor-Groesse ueber die Anzahl autorisierter Clients messen
//!     (Kapazitaetsgrenze pro Kompartiment, gesamtkonzept.md §2.2).
//!
//! Es findet kein Netzverkehr statt.

use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};

use rand::SeedableRng;
use tor_checkable::{SelfSigned, Timebound};
use tor_hscrypto::pk::{HsClientDescEncKeypair, HsIdKeypair};
use tor_hscrypto::time::TimePeriod;
use tor_linkspec::LinkSpec;
use tor_llcrypto::pk::curve25519;
use tor_llcrypto::pk::ed25519;
use tor_netdoc::NetdocBuilder;
use tor_netdoc::doc::hsdesc::{HsDesc, HsDescBuilder, IntroPointDesc, create_desc_sign_key_cert};

/// Anzahl autorisierter Clients im Haupttest.
const AUTHORIZED_CLIENTS: usize = 8;
/// Anzahl Entschluesselungsversuche je nicht autorisiertem Fall.
const UNAUTHORIZED_TRIALS: usize = 500;
/// Lebensdauer des Descriptors in Minuten.
const LIFETIME_MINS: u16 = 180;

struct Fixture {
    blinded_id: tor_hscrypto::pk::HsBlindIdKeypair,
    subcredential: tor_hscrypto::Subcredential,
    hs_desc_sign: ed25519::Keypair,
    intro_points: Vec<IntroPointDesc>,
    expiry: SystemTime,
    now: SystemTime,
}

fn curve25519_pk<R: rand::Rng + rand::CryptoRng>(rng: &mut R) -> curve25519::PublicKey {
    let sk = curve25519::EphemeralSecret::random_from_rng(rng);
    (&sk).into()
}

fn make_fixture<R: rand::Rng + rand::CryptoRng>(rng: &mut R, num_ipts: usize) -> Fixture {
    let now = SystemTime::now();
    let hs_id = ed25519::Keypair::generate(rng);
    let hs_desc_sign = ed25519::Keypair::generate(rng);

    // Zeitperiode, die "jetzt" enthaelt.
    let period = TimePeriod::new(
        Duration::from_secs(24 * 3600),
        now,
        Duration::from_secs(12 * 3600),
    )
    .expect("time period");

    let (_, blinded_id, subcredential) =
        HsIdKeypair::from(ed25519::ExpandedKeypair::from(&hs_id))
            .compute_blinded_key(period)
            .expect("blinded key");

    let intro_points = (0..num_ipts)
        .map(|i| {
            IntroPointDesc::builder()
                .link_specifiers(vec![
                    LinkSpec::OrPort(Ipv4Addr::new(127, 0, 0, 1).into(), 9000 + i as u16)
                        .encode()
                        .expect("linkspec"),
                ])
                .ipt_kp_ntor(curve25519_pk(rng))
                .kp_hs_ipt_sid(ed25519::Keypair::generate(rng).verifying_key().into())
                .kp_hss_ntor(curve25519_pk(rng).into())
                .build()
                .expect("intro point desc")
        })
        .collect();

    Fixture {
        blinded_id,
        subcredential,
        hs_desc_sign,
        intro_points,
        expiry: now + Duration::from_secs(3600),
        now,
    }
}

/// Baut und signiert einen Descriptor. `auth_clients = None` => Client-Auth aus.
fn build_descriptor<R: rand::Rng + rand::CryptoRng>(
    f: &Fixture,
    auth_clients: Option<&[curve25519::PublicKey]>,
    rng: &mut R,
) -> String {
    let cert = create_desc_sign_key_cert(
        &f.hs_desc_sign.verifying_key(),
        &f.blinded_id,
        f.expiry,
    )
    .expect("desc sign key cert");

    let blinded_pk = (&f.blinded_id).into();
    let mut builder = HsDescBuilder::default()
        .blinded_id(&blinded_pk)
        .hs_desc_sign(&f.hs_desc_sign)
        .hs_desc_sign_cert(cert)
        .create2_formats(&[tor_cell::chancell::msg::HandshakeType::NTOR])
        .auth_required(None)
        .is_single_onion_service(false)
        .intro_points(&f.intro_points)
        .intro_auth_key_cert_expiry(f.expiry)
        .intro_enc_key_cert_expiry(f.expiry)
        .lifetime(LIFETIME_MINS.into())
        .revision_counter(1.into())
        .subcredential(f.subcredential);

    if let Some(clients) = auth_clients {
        builder = builder.auth_clients(Some(clients));
    }

    builder.build_sign(rng).expect("build_sign")
}

/// Wie `build_descriptor`, aber ohne Panik — fuer den Leerfall-Test.
fn try_build_descriptor<R: rand::Rng + rand::CryptoRng>(
    f: &Fixture,
    auth_clients: Option<&[curve25519::PublicKey]>,
    rng: &mut R,
) -> Result<String, String> {
    let cert =
        create_desc_sign_key_cert(&f.hs_desc_sign.verifying_key(), &f.blinded_id, f.expiry)
            .map_err(|e| format!("{e}"))?;
    let blinded_pk = (&f.blinded_id).into();
    HsDescBuilder::default()
        .blinded_id(&blinded_pk)
        .hs_desc_sign(&f.hs_desc_sign)
        .hs_desc_sign_cert(cert)
        .create2_formats(&[tor_cell::chancell::msg::HandshakeType::NTOR])
        .auth_required(None)
        .is_single_onion_service(false)
        .intro_points(&f.intro_points)
        .intro_auth_key_cert_expiry(f.expiry)
        .intro_enc_key_cert_expiry(f.expiry)
        .lifetime(LIFETIME_MINS.into())
        .revision_counter(1.into())
        .subcredential(f.subcredential)
        .auth_clients(auth_clients)
        .build_sign(rng)
        .map_err(|e| format!("{e}"))
}

/// Versucht, den Descriptor zu entschluesseln. `Ok(())` = Zugriff gelungen.
fn try_decrypt(
    f: &Fixture,
    encoded: &str,
    key: Option<&HsClientDescEncKeypair>,
) -> Result<(), String> {
    let blinded_id: tor_hscrypto::pk::HsBlindId =
        ed25519::Ed25519Identity::from(*f.blinded_id.as_ref().public()).into();

    let enc = HsDesc::parse(encoded, &blinded_id)
        .map_err(|e| format!("parse: {e}"))?
        .check_signature()
        .map_err(|e| format!("outer signature: {e}"))?
        .check_valid_at(&f.now)
        .map_err(|e| format!("outer timeliness: {e}"))?;

    let _desc = enc
        .decrypt(&f.subcredential, key)
        .map_err(|e| format!("decrypt: {e}"))?
        .check_valid_at(&f.now)
        .map_err(|e| format!("inner timeliness: {e}"))?
        .check_signature()
        .map_err(|e| format!("inner signature: {e}"))?;

    Ok(())
}

fn main() {
    // Deterministischer RNG fuer Reproduzierbarkeit des Laufs.
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x5715_0001);

    println!("# Spike S1 — Descriptor Client-Auth (Restricted Discovery), offline");
    println!("# arti-Crates: tor-netdoc 0.44.0 / tor-hscrypto 0.44.0");
    println!();

    let f = make_fixture(&mut rng, 3);

    // --- Autorisierte Clients erzeugen ---
    let auth_kps: Vec<HsClientDescEncKeypair> = (0..AUTHORIZED_CLIENTS)
        .map(|_| HsClientDescEncKeypair::generate(&mut rng))
        .collect();
    let auth_pks: Vec<curve25519::PublicKey> =
        auth_kps.iter().map(|kp| *kp.public().as_ref()).collect();

    // --- Descriptor MIT Client-Auth ---
    let desc_auth = build_descriptor(&f, Some(&auth_pks), &mut rng);
    println!("[T1] Descriptor mit Client-Auth gebaut");
    println!("     autorisierte Clients : {AUTHORIZED_CLIENTS}");
    println!("     Intro-Points         : {}", f.intro_points.len());
    println!("     Descriptor-Groesse   : {} Bytes", desc_auth.len());
    println!();

    // --- T2: autorisierte Clients muessen Zugriff bekommen ---
    let mut ok = 0usize;
    let mut fail = 0usize;
    for kp in &auth_kps {
        match try_decrypt(&f, &desc_auth, Some(kp)) {
            Ok(()) => ok += 1,
            Err(e) => {
                fail += 1;
                println!("     UNERWARTET: autorisierter Client scheitert: {e}");
            }
        }
    }
    println!("[T2] autorisierte Entschluesselungsversuche: {AUTHORIZED_CLIENTS}");
    println!("     erfolgreich: {ok}   gescheitert: {fail}");
    let t2_pass = ok == AUTHORIZED_CLIENTS && fail == 0;
    println!("     ERGEBNIS: {}", if t2_pass { "PASS" } else { "FAIL" });
    println!();

    // --- T3: nicht autorisierte Clients duerfen keinen Zugriff bekommen ---
    let mut denied = 0usize;
    let mut leaked = 0usize;
    for _ in 0..UNAUTHORIZED_TRIALS {
        let intruder = HsClientDescEncKeypair::generate(&mut rng);
        match try_decrypt(&f, &desc_auth, Some(&intruder)) {
            Ok(()) => leaked += 1,
            Err(_) => denied += 1,
        }
    }
    println!("[T3] nicht-autorisierte Clients (frischer Key je Versuch): {UNAUTHORIZED_TRIALS}");
    println!("     abgewiesen: {denied}   durchgekommen: {leaked}");
    let t3_pass = leaked == 0 && denied == UNAUTHORIZED_TRIALS;
    println!(
        "     Abweisungsquote: {:.4} %",
        100.0 * denied as f64 / UNAUTHORIZED_TRIALS as f64
    );
    println!("     ERGEBNIS: {}", if t3_pass { "PASS" } else { "FAIL" });
    println!();

    // --- T4: Abruf ohne jeden Key (HSDir / netzweiter Scanner) ---
    let mut denied_nokey = 0usize;
    let mut leaked_nokey = 0usize;
    for _ in 0..UNAUTHORIZED_TRIALS {
        match try_decrypt(&f, &desc_auth, None) {
            Ok(()) => leaked_nokey += 1,
            Err(_) => denied_nokey += 1,
        }
    }
    println!("[T4] Abruf ohne Client-Key (HSDir-Beobachter/Enumerator): {UNAUTHORIZED_TRIALS}");
    println!("     abgewiesen: {denied_nokey}   durchgekommen: {leaked_nokey}");
    let t4_pass = leaked_nokey == 0;
    println!("     ERGEBNIS: {}", if t4_pass { "PASS" } else { "FAIL" });
    println!();

    // --- T5: Kontrolle — ohne Client-Auth ist der Descriptor ohne Key lesbar ---
    let desc_open = build_descriptor(&f, None, &mut rng);
    let control = try_decrypt(&f, &desc_open, None);
    println!("[T5] Kontrolle: Descriptor OHNE Client-Auth, Abruf ohne Key");
    println!(
        "     Groesse: {} Bytes   Ergebnis: {}",
        desc_open.len(),
        match &control {
            Ok(()) => "lesbar (erwartet)".to_string(),
            Err(e) => format!("NICHT lesbar — Testaufbau fragwuerdig: {e}"),
        }
    );
    let t5_pass = control.is_ok();
    println!("     ERGEBNIS: {}", if t5_pass { "PASS" } else { "FAIL" });
    println!();

    // --- T6: Was der HSDir am Descriptor unterscheiden kann ---
    // Nur die Schluesselwoerter des aeusseren Dokuments sind fuer den HSDir
    // sichtbar; der Mittel-Layer ist superencrypted.
    let kw = |s: &str| -> Vec<String> {
        s.lines()
            .filter(|l| {
                !l.is_empty()
                    && !l.starts_with('-')
                    && l.chars().next().map(|c| c.is_ascii_lowercase()) == Some(true)
                    && l.contains(|c: char| c == ' ' || c == '\r')
                    || l.chars().all(|c| c.is_ascii_lowercase() || c == '-')
            })
            .map(|l| l.split(' ').next().unwrap_or("").to_string())
            .filter(|k| !k.is_empty() && k.chars().all(|c| c.is_ascii_lowercase() || c == '-'))
            .collect()
    };
    let kw_auth = kw(&desc_auth);
    let kw_open = kw(&desc_open);
    println!("[T6] Fuer den HSDir sichtbare Struktur (aeusseres Dokument)");
    println!("     Schluesselwoerter mit Client-Auth : {kw_auth:?}");
    println!("     Schluesselwoerter ohne Client-Auth: {kw_open:?}");
    println!("     Bytes mit / ohne Client-Auth: {} / {}", desc_auth.len(), desc_open.len());
    println!(
        "     Struktur unterscheidbar? {}",
        if kw_auth == kw_open && desc_auth.len() == desc_open.len() {
            "nein (gleiche Keywords, gleiche Laenge)"
        } else {
            "JA — Client-Auth waere am Descriptor erkennbar"
        }
    );
    println!();

    // --- T7: Descriptor-Groesse vs. Anzahl autorisierter Clients ---
    println!("[T7] Descriptor-Groesse nach Anzahl autorisierter Clients (3 Intro-Points)");
    println!("     50-kB-Grenze = Konsensparameter HSV3MaxDescriptorSize");
    println!("     clients | bytes  | Status");
    let mut max_ok = 0usize;
    for n in [
        1usize, 5, 10, 20, 50, 60, 70, 80, 100, 160, 200, 300, 350, 400, 500,
    ] {
        let pks: Vec<curve25519::PublicKey> = (0..n)
            .map(|_| *HsClientDescEncKeypair::generate(&mut rng).public().as_ref())
            .collect();
        let d = build_descriptor(&f, Some(&pks), &mut rng);
        let over = d.len() > 50_000;
        println!(
            "     {n:>7} | {:>6} | {}",
            d.len(),
            if over { "ueber 50 kB" } else { "ok" }
        );
        if !over {
            max_ok = n;
        }
    }
    println!("     groesste getestete Clientzahl unter 50 kB: {max_ok}");
    println!(
        "     Bibliotheks-Empfehlung MAX_RESTRICTED_DISCOVERY_CLIENTS: {}",
        160
    );
    println!();

    // --- T8: Kompartiment ohne verbleibende autorisierte Kontakte ---
    // Relevanter Vault-Fall: letzter Kontakt eines Kompartiments revoziert
    // (gesamtkonzept.md §2.2, granulare Revocation).
    let empty: [curve25519::PublicKey; 0] = [];
    let r = try_build_descriptor(&f, Some(&empty), &mut rng);
    println!("[T8] Client-Auth aktiv, aber 0 autorisierte Clients");
    match &r {
        Ok(d) => println!("     Descriptor gebaut ({} Bytes)", d.len()),
        Err(e) => println!(
            "     Fehler beim Bauen: {}",
            e.lines().next().unwrap_or(e).chars().take(160).collect::<String>()
        ),
    }
    println!(
        "     Doku sagt (tor-netdoc build.rs, auth_clients): \
         'If Some(&[]), restricted discovery is enabled, but there will be no authorized clients'"
    );
    println!(
        "     tatsaechliches Verhalten: {}",
        if r.is_ok() { "wie dokumentiert" } else { "Fehler (Bug/BadApiUsage) — Doku und Code weichen ab" }
    );
    println!();

    let all = t2_pass && t3_pass && t4_pass && t5_pass;
    println!("== GESAMT: {} ==", if all { "PASS" } else { "FAIL" });
    if !all {
        std::process::exit(1);
    }
}
