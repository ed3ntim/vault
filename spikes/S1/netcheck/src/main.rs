//! Spike S1 — Vorpruefung: ist das Tor-Netz aus dieser Umgebung ueberhaupt
//! erreichbar? Nur wenn ja, laesst sich Erfolgskriterium 2 der Spec
//! ("Onion-Aufbau < 20 s p50, < 60 s p95") messen.
//!
//! Es werden ausschliesslich TCP-Verbindungen zu den fest verdrahteten
//! Tor-Directory-Authorities versucht (dieselben Endpunkte, die auch ein
//! Tor-Bootstrap kontaktiert). Kein HTTP, keine anderen Ziele.
//! Adressen aus tor-dirmgr/tor-netdir Fallback-Listen (Stand: Tor-Konsens).

use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// (Name, ORPort-Adresse) der Tor-Directory-Authorities.
const AUTHORITIES: &[(&str, &str)] = &[
    ("moria1", "128.31.0.39:9101"),
    ("tor26", "86.59.21.38:443"),
    ("dizum", "45.66.35.11:443"),
    ("gabelmoo", "131.188.40.189:443"),
    ("dannenberg", "193.23.244.244:443"),
    ("maatuska", "171.25.193.9:80"),
    ("longclaw", "199.58.81.140:443"),
    ("bastet", "204.13.164.118:443"),
];

const TIMEOUT: Duration = Duration::from_secs(10);

fn main() {
    println!("# Spike S1 — Erreichbarkeit des Tor-Netzes aus dieser Umgebung");
    println!("# TCP-Connect-Test gegen Tor-Directory-Authorities, Timeout {TIMEOUT:?}");
    println!();

    let extra: Vec<(String, String)> = std::env::args()
        .skip(1)
        .map(|a| ("fallback".to_string(), a))
        .collect();
    let targets: Vec<(&str, &str)> = if extra.is_empty() {
        AUTHORITIES.to_vec()
    } else {
        extra
            .iter()
            .map(|(n, a)| (n.as_str(), a.as_str()))
            .collect()
    };

    let mut ok = 0usize;
    for (name, addr) in &targets {
        let sa: SocketAddr = match addr.parse() {
            Ok(s) => s,
            Err(e) => {
                println!("  {name:<12} {addr:<22} PARSE-FEHLER {e}");
                continue;
            }
        };
        let t0 = Instant::now();
        match TcpStream::connect_timeout(&sa, TIMEOUT) {
            Ok(_) => {
                ok += 1;
                println!("  {name:<12} {addr:<22} ERREICHBAR ({} ms)", t0.elapsed().as_millis());
            }
            Err(e) => {
                println!(
                    "  {name:<12} {addr:<22} NICHT ERREICHBAR nach {} ms: {} ({:?})",
                    t0.elapsed().as_millis(),
                    e,
                    e.kind()
                );
            }
        }
    }

    println!();
    println!("erreichbar: {ok} von {}", targets.len());
    println!(
        "Folgerung: {}",
        if ok > 0 {
            "Tor-Bootstrap grundsaetzlich moeglich -> Kriterium 2 messbar"
        } else {
            "kein Tor-Zugang -> Kriterium 2 in dieser Umgebung NICHT messbar"
        }
    );
}
