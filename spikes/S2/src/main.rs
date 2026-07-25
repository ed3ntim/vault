//! Spike S2 — Multi-Device-Ratchet-Sync (Runner).
//!
//! SPIKE-CODE. Gehoert nicht nach `core/` oder `app/`.
//!
//! Aufruf:
//!   cargo run --release -- <runs_pro_variante> [latency_mult] [out.jsonl]

mod crypto;
mod sim;
#[cfg(test)]
mod tests;
mod vendor_dr;

use rayon::prelude::*;
use sim::{Profile, RunCfg, RunResult, Variant};
use std::io::Write;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let runs: u64 = args
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);
    let latency_mult: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1);
    let out_path = args
        .get(3)
        .cloned()
        .unwrap_or_else(|| "data/results.jsonl".to_string());
    let max_attempts: u32 = args
        .get(4)
        .and_then(|s| s.parse().ok())
        .unwrap_or(sim::DEFAULT_MAX_ATTEMPTS);

    let seed_offset: u64 = args.get(5).and_then(|s| s.parse().ok()).unwrap_or(0);
    let filter = args.get(6).cloned().unwrap_or_else(|| "all".to_string());

    let variants: Vec<Variant> = match filter.as_str() {
        "A" => vec![Variant::A],
        "AR" => vec![Variant::AReconcile],
        "B" => vec![Variant::B],
        "A2" => vec![Variant::A2],
        _ => vec![Variant::A, Variant::AReconcile, Variant::B, Variant::A2],
    };
    let profiles = Profile::all();

    let mut cfgs: Vec<RunCfg> = Vec::new();
    for v in variants.iter() {
        for k in 0..runs {
            let i = k.wrapping_add(seed_offset);
            let p = profiles
                .get((i as usize) % profiles.len())
                .copied()
                .unwrap_or(Profile::Mixed);
            cfgs.push(RunCfg {
                // Gleicher Seed pro Index ueber alle Varianten -> identische
                // Szenarien, direkte Vergleichbarkeit.
                seed: 0x5EED_0000_0000_0000u64.wrapping_add(i),
                variant: *v,
                profile: p,
                n_msgs: 1000,
                latency_mult,
                max_attempts,
            });
        }
    }

    let t0 = std::time::Instant::now();
    let results: Vec<RunResult> = cfgs.par_iter().map(|c| sim::run(*c)).collect();
    let dt = t0.elapsed();

    if let Some(dir) = std::path::Path::new(&out_path).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    match std::fs::File::create(&out_path) {
        Ok(f) => {
            let mut w = std::io::BufWriter::new(f);
            for r in results.iter() {
                if let Ok(line) = serde_json::to_string(r) {
                    let _ = writeln!(w, "{}", line);
                }
            }
            let _ = w.flush();
        }
        Err(e) => println!("konnte {} nicht schreiben: {}", out_path, e),
    }

    println!(
        "Laeufe: {} ({} je Variante, Seed-Offset {}, Filter {}), Latenzmultiplikator {}, max_attempts {}, Laufzeit {:.1} s",
        results.len(),
        runs,
        seed_offset,
        filter,
        latency_mult,
        max_attempts,
        dt.as_secs_f64()
    );
    println!();
    summarize(&results);
}

fn summarize(rs: &[RunResult]) {
    let variants = ["A", "A-reconcile", "B", "A2"];
    println!(
        "{:<12} {:>6} {:>8} {:>9} {:>8} {:>8} {:>9} {:>9} {:>8} {:>9} {:>9} {:>8}",
        "Variante",
        "Laeufe",
        "Verlust",
        "unkonv.",
        "DupSup",
        "DupEcht",
        "skipMax",
        "skip>=1k",
        "Sonden",
        ">60s",
        "convMax_s",
        "ackDrop"
    );
    for v in variants.iter() {
        let sel: Vec<&RunResult> = rs.iter().filter(|r| r.variant == *v).collect();
        if sel.is_empty() {
            continue;
        }
        let n = sel.len();
        let lost: usize = sel.iter().map(|r| r.lost).sum();
        let unconv: usize = sel.iter().map(|r| r.unconverged).sum();
        let dup: usize = sel.iter().map(|r| r.dup_suppressed).sum();
        let dup_real: usize = sel.iter().map(|r| r.dup_missed_by_msgid).sum();
        let skip_max = sel.iter().map(|r| r.max_skipped_device).max().unwrap_or(0);
        let skip_hits = sel
            .iter()
            .filter(|r| r.max_skipped_device >= 1000 || r.skip_too_large > 0 || r.storage_full > 0)
            .count();
        let probes: usize = sel.iter().map(|r| r.probes).sum();
        let over: usize = sel.iter().map(|r| r.probes_over_60s).sum();
        let convmax = sel.iter().map(|r| r.conv_max_ms).max().unwrap_or(0);
        let ackdrop: usize = sel.iter().map(|r| r.ack_dropped).sum();
        println!(
            "{:<12} {:>6} {:>8} {:>9} {:>8} {:>8} {:>9} {:>9} {:>8} {:>9} {:>9.1} {:>8}",
            v,
            n,
            lost,
            unconv,
            dup,
            dup_real,
            skip_max,
            skip_hits,
            probes,
            over,
            convmax as f64 / 1000.0,
            ackdrop
        );
    }
    println!();
    println!(
        "{:<12} {:>10} {:>12} {:>10} {:>10} {:>12} {:>12} {:>10}",
        "Variante", "Divergenz", "decryptFail", "aufgegeb", "zugestellt", "p95_zust_s", "syncRecs", "Laeufe_ok"
    );
    for v in variants.iter() {
        let sel: Vec<&RunResult> = rs.iter().filter(|r| r.variant == *v).collect();
        if sel.is_empty() {
            continue;
        }
        let div: usize = sel.iter().map(|r| r.send_divergence).sum();
        let df: usize = sel.iter().map(|r| r.decrypt_fail_new).sum();
        let ab: usize = sel.iter().map(|r| r.undelivered_final).sum();
        let del: usize = sel.iter().map(|r| r.delivered).sum();
        let mut p95: Vec<u64> = sel.iter().map(|r| r.delivery_p95_ms).collect();
        p95.sort_unstable();
        let med = p95
            .get(p95.len().saturating_sub(1) / 2)
            .copied()
            .unwrap_or(0);
        let sr: usize = sel.iter().map(|r| r.sync_records).sum();
        let clean = sel
            .iter()
            .filter(|r| r.lost == 0 && r.dup_missed_by_msgid == 0 && r.unconverged == 0)
            .count();
        println!(
            "{:<12} {:>10} {:>12} {:>10} {:>10} {:>12.1} {:>12} {:>10}",
            v,
            div,
            df,
            ab,
            del,
            med as f64 / 1000.0,
            sr,
            clean
        );
    }
    println!();
    println!(
        "{:<12} {:>12} {:>12} {:>12} {:>16}",
        "Variante", "LinkSonden", "konvergiert", ">60s", "convMax_s"
    );
    for v in variants.iter() {
        let sel: Vec<&RunResult> = rs.iter().filter(|r| r.variant == *v).collect();
        if sel.is_empty() {
            continue;
        }
        let p: usize = sel.iter().map(|r| r.link_probes).sum();
        let c: usize = sel.iter().map(|r| r.link_converged).sum();
        let o: usize = sel.iter().map(|r| r.link_over_60s).sum();
        let m = sel.iter().map(|r| r.link_conv_max_ms).max().unwrap_or(0);
        let s: u64 = sel.iter().map(|r| r.link_conv_sum_ms).sum();
        println!(
            "{:<12} {:>12} {:>12} {:>12} {:>16.2}  (Mittel {:.2} s)",
            v,
            p,
            c,
            o,
            m as f64 / 1000.0,
            if c > 0 { s as f64 / c as f64 / 1000.0 } else { 0.0 }
        );
    }
}
