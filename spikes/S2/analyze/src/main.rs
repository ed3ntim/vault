//! Auswertung der S2-Rohdaten. Aufruf: `cargo run --release -- <datei.jsonl>`

use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::BufRead;

#[derive(Debug, Deserialize, Clone)]
struct R {
    variant: String,
    profile: String,
    n_devices: usize,
    n_msgs: usize,
    lost: usize,
    unconverged: usize,
    dup_suppressed: usize,
    dup_missed_by_msgid: usize,
    max_skipped_device: usize,
    max_skipped_contact: usize,
    probes: usize,
    probes_over_60s: usize,
    ack_dropped: usize,
    send_divergence: usize,
    decrypt_fail_new: usize,
    skip_too_large: usize,
    storage_full: usize,
    attempts: usize,
    delivered: usize,
    sync_records: usize,
    undelivered_final: usize,
    link_probes: usize,
    link_converged: usize,
    link_over_60s: usize,
    link_conv_max_ms: u64,
    link_conv_sum_ms: u64,
    link_hist: [usize; 7],
}

fn pct(v: &mut Vec<usize>, p: f64) -> usize {
    if v.is_empty() {
        return 0;
    }
    v.sort_unstable();
    let i = (((v.len() as f64) * p).ceil() as usize).saturating_sub(1);
    v.get(i.min(v.len() - 1)).copied().unwrap_or(0)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut rows: Vec<R> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    for path in args.iter().skip(1) {
        let f = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) => {
                println!("kann {} nicht oeffnen: {}", path, e);
                continue;
            }
        };
        let before = rows.len();
        for line in std::io::BufReader::new(f).lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<R>(&line) {
                Ok(r) => rows.push(r),
                Err(e) => println!("parse {}: {}", path, e),
            }
        }
        names.push(format!("{} ({})", path, rows.len().saturating_sub(before)));
    }
    println!("Dateien: {}", names.join(", "));
    println!("Zeilen gesamt: {}", rows.len());
    println!();

    let variants = ["A", "A-reconcile", "B", "A2"];

    println!("=== Erfolgskriterien je Variante (alle Laeufe zusammengefasst) ===");
    println!(
        "{:<12} {:>7} {:>9} {:>10} {:>9} {:>9} {:>9} {:>10} {:>10}",
        "Variante",
        "Laeufe",
        "Nachr.",
        "Verlust",
        "Verl.%",
        "DupEcht",
        "Dup%",
        "unkonv.",
        "Laeufe0Fhl"
    );
    for v in variants.iter() {
        let sel: Vec<&R> = rows.iter().filter(|r| r.variant == *v).collect();
        if sel.is_empty() {
            continue;
        }
        let msgs: usize = sel.iter().map(|r| r.n_msgs).sum();
        let lost: usize = sel.iter().map(|r| r.lost).sum();
        let dup: usize = sel.iter().map(|r| r.dup_missed_by_msgid).sum();
        let unc: usize = sel.iter().map(|r| r.unconverged).sum();
        let clean = sel
            .iter()
            .filter(|r| r.lost == 0 && r.dup_missed_by_msgid == 0 && r.unconverged == 0)
            .count();
        println!(
            "{:<12} {:>7} {:>9} {:>10} {:>8.3}% {:>9} {:>8.4}% {:>10} {:>10}",
            v,
            sel.len(),
            msgs,
            lost,
            100.0 * lost as f64 / msgs as f64,
            dup,
            100.0 * dup as f64 / msgs as f64,
            unc,
            clean
        );
    }

    println!();
    println!("=== skipped_message_keys (Kriterium: < 1000 je Session) ===");
    println!(
        "{:<12} {:>10} {:>10} {:>10} {:>10} {:>12} {:>12}",
        "Variante", "p50", "p95", "p99", "max", "Laeufe>=1000", "SkipTooLarge"
    );
    for v in variants.iter() {
        let sel: Vec<&R> = rows.iter().filter(|r| r.variant == *v).collect();
        if sel.is_empty() {
            continue;
        }
        let mut vals: Vec<usize> = sel.iter().map(|r| r.max_skipped_device).collect();
        let mx = vals.iter().copied().max().unwrap_or(0);
        let over = sel.iter().filter(|r| r.max_skipped_device >= 1000).count();
        let stl: usize = sel.iter().map(|r| r.skip_too_large + r.storage_full).sum();
        println!(
            "{:<12} {:>10} {:>10} {:>10} {:>10} {:>12} {:>12}",
            v,
            pct(&mut vals.clone(), 0.50),
            pct(&mut vals.clone(), 0.95),
            pct(&mut vals.clone(), 0.99),
            mx,
            over,
            stl
        );
    }
    println!();
    println!("   (Kontaktseite)");
    for v in variants.iter() {
        let sel: Vec<&R> = rows.iter().filter(|r| r.variant == *v).collect();
        if sel.is_empty() {
            continue;
        }
        let mut vals: Vec<usize> = sel.iter().map(|r| r.max_skipped_contact).collect();
        let mx = vals.iter().copied().max().unwrap_or(0);
        let over = sel.iter().filter(|r| r.max_skipped_contact >= 1000).count();
        println!(
            "{:<12} p50={:<6} p95={:<6} p99={:<6} p999={:<6} max={:<6} Laeufe>=1000: {} von {} ({:.3}%)",
            v,
            pct(&mut vals.clone(), 0.50),
            pct(&mut vals.clone(), 0.95),
            pct(&mut vals.clone(), 0.99),
            pct(&mut vals.clone(), 0.999),
            mx,
            over,
            sel.len(),
            100.0 * over as f64 / sel.len() as f64
        );
    }

    println!();
    println!("=== Konvergenz nach Wiederverbindung (ab Verfuegbarkeit eines Geschwisters) ===");
    println!(
        "{:<12} {:>9} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>10} {:>10}",
        "Variante", "Sonden", "<1s", "<5s", "<15s", "<60s", "<300s", "<1h", ">=1h", "Anteil<60s", "max_s"
    );
    for v in variants.iter() {
        let sel: Vec<&R> = rows.iter().filter(|r| r.variant == *v).collect();
        if sel.is_empty() {
            continue;
        }
        let mut h = [0usize; 7];
        for r in sel.iter() {
            for i in 0..7 {
                if let (Some(a), Some(b)) = (h.get_mut(i), r.link_hist.get(i)) {
                    *a = a.saturating_add(*b);
                }
            }
        }
        let tot: usize = h.iter().sum();
        let under60: usize = h.iter().take(4).sum();
        let mx = sel.iter().map(|r| r.link_conv_max_ms).max().unwrap_or(0);
        println!(
            "{:<12} {:>9} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>9.2}% {:>10.1}",
            v,
            tot,
            h.first().copied().unwrap_or(0),
            h.get(1).copied().unwrap_or(0),
            h.get(2).copied().unwrap_or(0),
            h.get(3).copied().unwrap_or(0),
            h.get(4).copied().unwrap_or(0),
            h.get(5).copied().unwrap_or(0),
            h.get(6).copied().unwrap_or(0),
            if tot > 0 {
                100.0 * under60 as f64 / tot as f64
            } else {
                0.0
            },
            mx as f64 / 1000.0
        );
    }

    println!();
    println!("=== Zustellung und Ratchet-Gesundheit ===");
    println!(
        "{:<12} {:>12} {:>12} {:>12} {:>12} {:>12} {:>12}",
        "Variante", "zugestellt", "nieZugest.", "ackVerw.", "Divergenz", "decryptFail", "Versuche"
    );
    for v in variants.iter() {
        let sel: Vec<&R> = rows.iter().filter(|r| r.variant == *v).collect();
        if sel.is_empty() {
            continue;
        }
        println!(
            "{:<12} {:>12} {:>12} {:>12} {:>12} {:>12} {:>12}",
            v,
            sel.iter().map(|r| r.delivered).sum::<usize>(),
            sel.iter().map(|r| r.undelivered_final).sum::<usize>(),
            sel.iter().map(|r| r.ack_dropped).sum::<usize>(),
            sel.iter().map(|r| r.send_divergence).sum::<usize>(),
            sel.iter().map(|r| r.decrypt_fail_new).sum::<usize>(),
            sel.iter().map(|r| r.attempts).sum::<usize>(),
        );
    }

    println!();
    println!("=== Verlustrate je Szenarioprofil ===");
    println!(
        "{:<12} {:<24} {:>8} {:>10} {:>9} {:>10} {:>10}",
        "Variante", "Profil", "Laeufe", "Verlust", "Verl.%", "DupEcht", "skipMax"
    );
    let mut keys: BTreeMap<(String, String), Vec<&R>> = BTreeMap::new();
    for r in rows.iter() {
        keys.entry((r.variant.clone(), r.profile.clone()))
            .or_default()
            .push(r);
    }
    for ((v, p), sel) in keys.iter() {
        let msgs: usize = sel.iter().map(|r| r.n_msgs).sum();
        let lost: usize = sel.iter().map(|r| r.lost).sum();
        let dup: usize = sel.iter().map(|r| r.dup_missed_by_msgid).sum();
        let sk = sel.iter().map(|r| r.max_skipped_device).max().unwrap_or(0);
        println!(
            "{:<12} {:<24} {:>8} {:>10} {:>8.3}% {:>10} {:>10}",
            v,
            p,
            sel.len(),
            lost,
            100.0 * lost as f64 / msgs as f64,
            dup,
            sk
        );
    }

    println!();
    println!("=== Geraetezahl ===");
    for v in variants.iter() {
        for n in 2..=3usize {
            let sel: Vec<&R> = rows
                .iter()
                .filter(|r| r.variant == *v && r.n_devices == n)
                .collect();
            if sel.is_empty() {
                continue;
            }
            let msgs: usize = sel.iter().map(|r| r.n_msgs).sum();
            let lost: usize = sel.iter().map(|r| r.lost).sum();
            let dup: usize = sel.iter().map(|r| r.dup_missed_by_msgid).sum();
            println!(
                "{:<12} {} Geraete: Laeufe={:<6} Verlust={:<8} ({:.3}%)  DupEcht={}",
                v,
                n,
                sel.len(),
                lost,
                100.0 * lost as f64 / msgs as f64,
                dup
            );
        }
    }

    println!();
    println!("=== Aufwand ===");
    for v in variants.iter() {
        let sel: Vec<&R> = rows.iter().filter(|r| r.variant == *v).collect();
        if sel.is_empty() {
            continue;
        }
        let sr: usize = sel.iter().map(|r| r.sync_records).sum();
        let msgs: usize = sel.iter().map(|r| r.n_msgs).sum();
        let at: usize = sel.iter().map(|r| r.attempts).sum();
        println!(
            "{:<12} SyncRecords/Nachricht={:.2}   Zustellversuche/Nachricht={:.2}",
            v,
            sr as f64 / msgs as f64,
            at as f64 / msgs as f64
        );
    }
    println!();
    println!("Hinweis: DupSup gesamt");
    for v in variants.iter() {
        let sel: Vec<&R> = rows.iter().filter(|r| r.variant == *v).collect();
        if sel.is_empty() {
            continue;
        }
        println!(
            "  {:<12} dup_suppressed={:<8} davon von msg_id (§8) nicht erkennbar={}",
            v,
            sel.iter().map(|r| r.dup_suppressed).sum::<usize>(),
            sel.iter().map(|r| r.dup_missed_by_msgid).sum::<usize>()
        );
    }
    let _ = rows.iter().map(|r| r.probes + r.probes_over_60s + r.link_probes + r.link_converged).sum::<usize>();
}
