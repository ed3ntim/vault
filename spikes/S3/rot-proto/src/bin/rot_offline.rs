//! Spike S3 — Messprogramm, offline.
//!
//! Misst alles an der erzwungenen Intro-Point-Rotation, was **ohne** ein
//! funktionierendes Tor-Netz messbar ist:
//!
//!   R1  Ausgangslage: Descriptor der Epoche e, alle Kontakte haben Zugriff
//!   R2  Nach Revocation: revozierter Kontakt kommt an den neuen Descriptor
//!       nicht heran; alle uebrigen schon
//!   R3  Die Intro-Point-Saetze der Epochen e und e+1 sind disjunkt
//!       (die Rotation ist im Descriptor tatsaechlich sichtbar)
//!   R4  Der revozierte Kontakt behaelt seinen **zwischengespeicherten**
//!       Descriptor der Epoche e — inkl. der alten Intro-Point-Schluessel.
//!       Damit ist belegt, warum der Republish allein nicht revoziert.
//!   R5  revision-counter waechst monoton (sonst verwirft der HSDir)
//!   R6  Dauer des lokalen Anteils einer Revocation (p50/p95/max),
//!       beide Reihenfolgen (TeardownFirst / MakeBeforeBreak)
//!   R7  Leerfall: letzter Kontakt eines Kompartiments revoziert
//!   R8  Skalierung des lokalen Anteils ueber die Kontaktzahl
//!
//! Kein Netzverkehr. Was hier NICHT gemessen wird, steht in `BERICHT.md`.

use std::time::{Duration, Instant};

use rot_proto::desc::{
    self, Access, LocalTransport, ServiceIdentity, ARTI_DESCRIPTOR_LIFETIME_MINS,
};
use rot_proto::stats::{self, ms};
use rot_proto::{revoke, Compartment, RotationOrder, RotationTransport};
use tor_hscrypto::pk::HsClientDescEncKeypair;

const CLIENTS: usize = 8;
const INTRO_POINTS: usize = 3;
const DENY_TRIALS: usize = 500;
const TIMING_RUNS: usize = 200;

fn pk_of(kp: &HsClientDescEncKeypair) -> tor_llcrypto::pk::curve25519::PublicKey {
    *kp.public().as_ref()
}

fn main() {
    let mut rng = desc::rng_from_seed(0x5335_0001);

    println!("# Spike S3 — erzwungene Intro-Point-Rotation, offline");
    println!("# spec/protokoll-spec.md §11 · ADR-15 · spec/phase0-spikeplan.md §3 (S3)");
    println!("# Bibliothek: tor-netdoc 0.44.0 / tor-hscrypto 0.44.0 (derselbe Pfad,");
    println!("#             den tor-hsservice/src/publish/descriptor.rs nimmt)");
    println!("# Kein Netzverkehr.");
    println!();

    let id = match ServiceIdentity::generate(&mut rng) {
        Ok(i) => i,
        Err(e) => {
            println!("Abbruch: Identitaet nicht erzeugbar: {e:?}");
            std::process::exit(2);
        }
    };

    // Client-Auth-Schluessel der 8 Kontakte. Kontakt 7 wird revoziert.
    let client_kps = desc::make_clients(&mut rng, CLIENTS);
    let revoked_idx = CLIENTS - 1;

    let mut comp = Compartment::new(0);
    for (i, kp) in client_kps.iter().enumerate() {
        comp.authorized_clients.insert(i as u32, pk_of(kp));
        comp.mesh_visibility.insert(i as u32, [i as u8; 32]);
        comp.sessions.insert(i as u32, vec![0xAA; 128]);
    }

    let mut transport = LocalTransport::new(id, desc::rng_from_seed(0x5335_0002));

    // ---------------- R1: Ausgangslage ----------------------------------
    let ipts_e0 = match transport.establish_intro_points(0, INTRO_POINTS) {
        Ok(v) => v,
        Err(e) => {
            println!("Abbruch: Intro-Points nicht erzeugbar: {e:?}");
            std::process::exit(2);
        }
    };
    comp.intro_points = ipts_e0;
    comp.revision_counter = 1;
    let clients_e0: Vec<_> = comp.authorized_clients.values().copied().collect();
    let desc_e0_bytes = match transport.publish_descriptor(0, 1, &clients_e0, &comp.intro_points) {
        Ok(b) => b,
        Err(e) => {
            println!("Abbruch: Descriptor Epoche 0 nicht baubar: {e:?}");
            std::process::exit(2);
        }
    };
    comp.published = true;
    let desc_e0 = String::from_utf8_lossy(&desc_e0_bytes).to_string();

    let mut ok_e0 = 0usize;
    let mut ipts_seen_by_revoked_e0: Vec<Vec<u8>> = Vec::new();
    for (i, kp) in client_kps.iter().enumerate() {
        match desc::try_access(&transport.id, &desc_e0, Some(kp)) {
            Access::Granted(fps) => {
                ok_e0 += 1;
                if i == revoked_idx {
                    ipts_seen_by_revoked_e0 = fps;
                }
            }
            Access::Denied(e) => println!("     UNERWARTET: Kontakt {i} abgewiesen: {e}"),
        }
    }
    println!("[R1] Ausgangslage — Epoche 0, {CLIENTS} autorisierte Kontakte, {INTRO_POINTS} Intro-Points");
    println!("     Descriptor-Groesse            : {} Bytes", desc_e0.len());
    println!("     descriptor-lifetime (Minuten) : {ARTI_DESCRIPTOR_LIFETIME_MINS}");
    println!("     Kontakte mit Zugriff          : {ok_e0} von {CLIENTS}");
    println!(
        "     Intro-Points, die Kontakt {revoked_idx} sieht: {}",
        ipts_seen_by_revoked_e0.len()
    );
    let r1_pass = ok_e0 == CLIENTS && ipts_seen_by_revoked_e0.len() == INTRO_POINTS;
    println!("     ERGEBNIS: {}", if r1_pass { "PASS" } else { "FAIL" });
    println!();

    // ---------------- Revocation (§11) ----------------------------------
    let outcome = match revoke(
        &mut comp,
        &mut transport,
        revoked_idx as u32,
        RotationOrder::TeardownFirst,
        INTRO_POINTS,
    ) {
        Ok(o) => o,
        Err(e) => {
            println!("Abbruch: Revocation gescheitert: {e:?}");
            std::process::exit(2);
        }
    };
    let desc_e1 = match transport.last_descriptor() {
        Some(d) => d.clone(),
        None => {
            println!("Abbruch: kein Descriptor nach Revocation");
            std::process::exit(2);
        }
    };

    // ---------------- R2: Zugriff nach Revocation -----------------------
    let mut denied = 0usize;
    let mut leaked = 0usize;
    for _ in 0..DENY_TRIALS {
        match desc::try_access(&transport.id, &desc_e1, Some(&client_kps[revoked_idx])) {
            Access::Granted(_) => leaked += 1,
            Access::Denied(_) => denied += 1,
        }
    }
    let mut remaining_ok = 0usize;
    let mut ipts_e1: Vec<Vec<u8>> = Vec::new();
    for (i, kp) in client_kps.iter().enumerate() {
        if i == revoked_idx {
            continue;
        }
        match desc::try_access(&transport.id, &desc_e1, Some(kp)) {
            Access::Granted(fps) => {
                remaining_ok += 1;
                ipts_e1 = fps;
            }
            Access::Denied(e) => println!("     UNERWARTET: Kontakt {i} abgewiesen: {e}"),
        }
    }
    println!("[R2] Nach Revocation von Kontakt {revoked_idx} — Epoche {}", comp.intro_point_epoch);
    println!("     Abrufversuche des Revozierten am NEUEN Descriptor: {DENY_TRIALS}");
    println!("     abgewiesen: {denied}   durchgekommen: {leaked}");
    println!(
        "     Abweisungsquote: {:.4} %",
        100.0 * denied as f64 / DENY_TRIALS as f64
    );
    println!("     verbliebene Kontakte mit Zugriff: {remaining_ok} von {}", CLIENTS - 1);
    let r2_pass = leaked == 0 && remaining_ok == CLIENTS - 1;
    println!("     ERGEBNIS: {}", if r2_pass { "PASS" } else { "FAIL" });
    println!();

    // ---------------- R3: Rotation im Descriptor sichtbar ---------------
    let disjoint = ipts_e1
        .iter()
        .all(|f| !ipts_seen_by_revoked_e0.contains(f));
    println!("[R3] Intro-Point-Rotation im Descriptor");
    println!("     Intro-Points Epoche 0: {}", ipts_seen_by_revoked_e0.len());
    println!("     Intro-Points Epoche 1: {}", ipts_e1.len());
    println!(
        "     Schnittmenge der Intro-Point-Schluessel: {}",
        ipts_e1
            .iter()
            .filter(|f| ipts_seen_by_revoked_e0.contains(f))
            .count()
    );
    println!("     abgerissene Intro-Points laut Transport: {}", outcome.timeline.withdrawn);
    let r3_pass = disjoint && ipts_e1.len() == INTRO_POINTS && outcome.timeline.withdrawn == INTRO_POINTS;
    println!("     ERGEBNIS: {}", if r3_pass { "PASS" } else { "FAIL" });
    println!();

    // ---------------- R4: zwischengespeicherter alter Descriptor --------
    // Der Kern des Spikes: der Revozierte braucht den neuen Descriptor gar
    // nicht. Er hat den alten.
    let cached = desc::try_access(&transport.id, &desc_e0, Some(&client_kps[revoked_idx]));
    let (cached_ok, cached_ipts) = match &cached {
        Access::Granted(f) => (true, f.len()),
        Access::Denied(_) => (false, 0),
    };
    println!("[R4] Zwischengespeicherter Descriptor der Epoche 0, gelesen NACH der Revocation");
    println!(
        "     Revozierter kann alten Descriptor weiter lesen: {}",
        if cached_ok { "JA" } else { "nein" }
    );
    println!("     darin enthaltene Intro-Point-Schluessel: {cached_ipts}");
    println!(
        "     Gueltigkeitsfenster des alten Descriptors (descriptor-lifetime): {} min",
        ARTI_DESCRIPTOR_LIFETIME_MINS
    );
    println!("     Folge: der Republish allein entzieht nichts. Wirksam wird die");
    println!("            Revocation erst durch den Abriss der alten Intro-Points.");
    println!();

    // ---------------- R5: revision-counter ------------------------------
    let rev = |d: &str| -> Option<u64> {
        d.lines()
            .find(|l| l.starts_with("revision-counter "))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u64>().ok())
    };
    let r0 = rev(&desc_e0);
    let r1 = rev(&desc_e1);
    println!("[R5] revision-counter (fuer den HSDir im Klartext sichtbar)");
    println!("     Epoche 0: {r0:?}   Epoche 1: {r1:?}");
    let r5_pass = matches!((r0, r1), (Some(a), Some(b)) if b > a);
    println!(
        "     monoton wachsend: {}",
        if r5_pass { "ja" } else { "NEIN — HSDir wuerde den neuen Descriptor verwerfen" }
    );
    println!("     ERGEBNIS: {}", if r5_pass { "PASS" } else { "FAIL" });
    println!();

    // ---------------- R6: Dauer des lokalen Anteils ---------------------
    println!("[R6] Dauer des LOKALEN Anteils einer Revocation ({TIMING_RUNS} Laeufe je Reihenfolge)");
    println!("     enthalten: Credential-Entzug, epoch += 1, frische Intro-Point-Schluessel,");
    println!("               Descriptor bauen+signieren, Mesh-Entzug, Session-Purge");
    println!("     NICHT enthalten: Circuit-Abriss, ESTABLISH_INTRO, HSDir-Upload (Netz)");
    println!();
    println!("     Reihenfolge          | n   | min        | p50        | p95        | max");
    for order in [RotationOrder::TeardownFirst, RotationOrder::MakeBeforeBreak] {
        let mut totals: Vec<Duration> = Vec::with_capacity(TIMING_RUNS);
        let mut desc_only: Vec<Duration> = Vec::with_capacity(TIMING_RUNS);
        for run in 0..TIMING_RUNS {
            let mut rng2 = desc::rng_from_seed(0x5335_1000 + run as u64);
            let idl = match ServiceIdentity::generate(&mut rng2) {
                Ok(i) => i,
                Err(_) => continue,
            };
            let kps = desc::make_clients(&mut rng2, CLIENTS);
            let mut c = Compartment::new(0);
            for (i, kp) in kps.iter().enumerate() {
                c.authorized_clients.insert(i as u32, pk_of(kp));
                c.mesh_visibility.insert(i as u32, [0u8; 32]);
                c.sessions.insert(i as u32, vec![0xAA; 128]);
            }
            let mut tr = LocalTransport::new(idl, desc::rng_from_seed(0x5335_2000 + run as u64));
            if let Ok(v) = tr.establish_intro_points(0, INTRO_POINTS) {
                c.intro_points = v;
            }
            let t_desc = Instant::now();
            let _ = tr.publish_descriptor(
                0,
                1,
                &c.authorized_clients.values().copied().collect::<Vec<_>>(),
                &c.intro_points,
            );
            desc_only.push(t_desc.elapsed());
            if let Ok(o) = revoke(&mut c, &mut tr, revoked_idx as u32, order, INTRO_POINTS) {
                totals.push(o.timeline.t_total);
            }
        }
        let s = stats::summarize(totals);
        let label = match order {
            RotationOrder::TeardownFirst => "TeardownFirst      ",
            RotationOrder::MakeBeforeBreak => "MakeBeforeBreak    ",
        };
        println!(
            "     {label} | {:>3} | {:>10} | {:>10} | {:>10} | {:>10}",
            s.n,
            ms(s.min),
            ms(s.p50),
            ms(s.p95),
            ms(s.max)
        );
        if matches!(order, RotationOrder::TeardownFirst) {
            let d = stats::summarize(desc_only);
            println!(
                "     davon nur Descriptor  | {:>3} | {:>10} | {:>10} | {:>10} | {:>10}",
                d.n,
                ms(d.min),
                ms(d.p50),
                ms(d.p95),
                ms(d.max)
            );
        }
    }
    println!();
    println!("     Kriterium spec/phase0-spikeplan.md §3 (S3): p95 < 300 s");
    println!("     ACHTUNG: der hier gemessene Wert ist NICHT das Kriterium. Er ist der");
    println!("     lokale Sockel; die messbestimmenden Netzanteile fehlen (siehe BERICHT.md §4).");
    println!();

    // ---------------- R7: Leerfall --------------------------------------
    {
        let mut rng3 = desc::rng_from_seed(0x5335_3000);
        let idl = match ServiceIdentity::generate(&mut rng3) {
            Ok(i) => i,
            Err(e) => {
                println!("[R7] Abbruch: {e:?}");
                return;
            }
        };
        let kps = desc::make_clients(&mut rng3, 1);
        let mut c = Compartment::new(1);
        c.authorized_clients.insert(0, pk_of(&kps[0]));
        let mut tr = LocalTransport::new(idl, desc::rng_from_seed(0x5335_3001));
        if let Ok(v) = tr.establish_intro_points(0, INTRO_POINTS) {
            c.intro_points = v;
        }
        let published_before = tr.published.len();
        let res = revoke(&mut c, &mut tr, 0, RotationOrder::TeardownFirst, INTRO_POINTS);
        println!("[R7] Leerfall: letzter Kontakt des Kompartiments revoziert");
        println!("     Ergebnis der Revocation      : {}", if res.is_ok() { "ok" } else { "Fehler" });
        println!("     Descriptor neu veroeffentlicht: {}", tr.published.len() - published_before);
        println!("     unpublish() aufgerufen        : {}", tr.unpublished);
        println!("     Kompartiment publiziert       : {}", c.published);
        println!("     Begruendung: ADR-16 Punkt 6 — ein Kompartiment ohne autorisierte");
        println!("     Kontakte wird nicht publiziert (Arti: Bug/BadApiUsage bei 0 Clients, S1/T8).");
        let r7_pass = res.is_ok() && tr.unpublished && !c.published;
        println!("     ERGEBNIS: {}", if r7_pass { "PASS" } else { "FAIL" });
        println!();
    }

    // ---------------- R8: Skalierung ------------------------------------
    println!("[R8] Lokaler Anteil ueber die Zahl verbleibender Kontakte (20 Laeufe je Punkt)");
    println!("     Kontakte | p50        | p95        | Descriptor-Bytes");
    for n in [1usize, 5, 10, 20, 40, 80] {
        let mut v: Vec<Duration> = Vec::new();
        let mut bytes = 0usize;
        for run in 0..20 {
            let mut rng4 = desc::rng_from_seed(0x5335_4000 + (n * 100 + run) as u64);
            let idl = match ServiceIdentity::generate(&mut rng4) {
                Ok(i) => i,
                Err(_) => continue,
            };
            let kps = desc::make_clients(&mut rng4, n + 1);
            let mut c = Compartment::new(0);
            for (i, kp) in kps.iter().enumerate() {
                c.authorized_clients.insert(i as u32, pk_of(kp));
            }
            let mut tr = LocalTransport::new(idl, desc::rng_from_seed(0x5335_5000 + run as u64));
            if let Ok(x) = tr.establish_intro_points(0, INTRO_POINTS) {
                c.intro_points = x;
            }
            if let Ok(o) = revoke(&mut c, &mut tr, n as u32, RotationOrder::TeardownFirst, INTRO_POINTS)
            {
                v.push(o.timeline.t_total);
                bytes = o.timeline.descriptor_bytes;
            }
        }
        let s = stats::summarize(v);
        println!(
            "     {n:>8} | {:>10} | {:>10} | {bytes:>6}",
            ms(s.p50),
            ms(s.p95)
        );
    }
    println!();

    let all = r1_pass && r2_pass && r3_pass && r5_pass && cached_ok;
    println!("== Offline-Teil GESAMT: {} ==", if all { "PASS" } else { "FAIL" });
    println!();
    println!("Hinweis: PASS heisst hier ausschliesslich, dass die Rotationslogik und die");
    println!("Descriptor-Kryptografie tun, was §11 beschreibt. Das Erfolgskriterium von S3");
    println!("ist eine ZEIT im laufenden Tor-Netz und ist damit NICHT belegt.");
    if !all {
        std::process::exit(1);
    }
}
