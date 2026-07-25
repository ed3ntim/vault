//! CLI zu `s5-eval`. Siehe `spikes/S5/tools/README.md`.
//!
//! Exitcodes:
//!   0 = alle Kriterien bestanden
//!   1 = mindestens ein Kriterium gerissen
//!   2 = unentschieden / zu wenig Daten -> mehr Laeufe noetig
//!   3 = Eingabefehler, oder synthetische Daten ohne --allow-synthetic

#![forbid(unsafe_code)]

use s5_eval::csvlog::{self, RunPolicy};
use s5_eval::verdict::{self, Decision};
use s5_eval::{batterystats, history, thermal};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = r#"s5-eval — Auswertung Spike S5 (Akkuverbrauch unter Dauer-Onion)

  s5-eval run <samples.csv> [--min-hours H]
      Kennzahlen eines Einzellaufs (Entladerate %/24 h, Gueltigkeit).

  s5-eval verdict <verzeichnis> [--min-hours H] [--allow-synthetic]
      Alle *.csv unterhalb des Verzeichnisses einlesen, nach Geraet und
      Messreihe gruppieren und die Kriterien aus spec/phase0-spikeplan.md
      §2 (S5) entscheiden.

  s5-eval history <history.txt> [--out datei.csv] [--series R1] [--device DEV-A]
                  [--start-unix N] [--deltas]
      `dumpsys batterystats --history` in das Sample-CSV-Format umsetzen.

  s5-eval thermal <thermal.txt>
      `dumpsys thermalservice`-Dump(s) auf Throttling pruefen.

  s5-eval batterystats <checkin.txt> [--top N]
      `dumpsys batterystats --checkin` nach Verbrauchsanteilen aufschluesseln
      (informativ, nicht Gate-relevant).

Verzeichnisaufbau fuer `verdict`:
  <root>/R0/<lauf>.csv  R1/  R2/  R3/  R4/  R5/  K1/  K2/
  Die Messreihe wird aus `# series=` im Dateikopf gelesen, ersatzweise aus
  dem Verzeichnisnamen. Das Geraet aus `# device=`.
"#;

fn flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn opt(args: &[String], name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    args.get(i + 1).cloned()
}

fn positional(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut skip = false;
    for a in args.iter() {
        if skip {
            skip = false;
            continue;
        }
        if a.starts_with("--") {
            // Optionen mit Wert
            if matches!(
                a.as_str(),
                "--min-hours" | "--out" | "--series" | "--device" | "--start-unix" | "--top"
            ) {
                skip = true;
            }
            continue;
        }
        out.push(a.clone());
    }
    out
}

fn policy_from(args: &[String]) -> RunPolicy {
    let mut p = RunPolicy::default();
    if let Some(h) = opt(args, "--min-hours").and_then(|v| v.parse::<f64>().ok()) {
        p.min_hours = h;
    }
    p
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() || flag(&argv, "--help") || flag(&argv, "-h") {
        println!("{USAGE}");
        return ExitCode::from(0);
    }
    let cmd = argv[0].clone();
    let rest: Vec<String> = argv[1..].to_vec();
    let pos = positional(&rest);

    let res = match cmd.as_str() {
        "run" => cmd_run(&pos, &rest),
        "verdict" => return cmd_verdict(&pos, &rest),
        "history" => cmd_history(&pos, &rest),
        "thermal" => cmd_thermal(&pos),
        "batterystats" => cmd_batterystats(&pos, &rest),
        other => Err(format!("unbekanntes Kommando: {other}\n\n{USAGE}")),
    };

    match res {
        Ok(()) => ExitCode::from(0),
        Err(e) => {
            eprintln!("Fehler: {e}");
            ExitCode::from(3)
        }
    }
}

fn need_arg(pos: &[String], what: &str) -> Result<PathBuf, String> {
    pos.first()
        .map(PathBuf::from)
        .ok_or_else(|| format!("Pfad fehlt: {what}"))
}

fn cmd_run(pos: &[String], args: &[String]) -> Result<(), String> {
    let path = need_arg(pos, "<samples.csv>")?;
    let policy = policy_from(args);
    let log = csvlog::parse_file(&path)?;
    let m = csvlog::evaluate(&log, &policy)?;
    print_run(&m);
    Ok(())
}

fn print_run(m: &csvlog::RunMetrics) {
    println!("Lauf {}  Reihe {}  Geraet {}", m.id, m.series, m.device);
    println!("  Dauer                : {:.2} h ({} Messpunkte)", m.hours, m.n_samples);
    println!("  Fuellstand           : {:.0} % -> {:.0} %", m.level_start, m.level_end);
    println!(
        "  Entladerate          : {:.2} %/24 h   (Regression, r2 = {:.4}){}",
        m.drain_pct_per_24h,
        m.r2,
        if m.extrapolated { "  [hochgerechnet]" } else { "" }
    );
    match (m.drain_mah_per_24h, m.drain_pct_per_24h_coulomb) {
        (Some(mah), Some(pct)) => println!("  Coulomb-Counter      : {mah:.1} mAh/24 h = {pct:.2} %/24 h"),
        (Some(mah), None) => println!("  Coulomb-Counter      : {mah:.1} mAh/24 h (design_capacity_uah fehlt)"),
        _ => println!("  Coulomb-Counter      : nicht verfuegbar"),
    }
    match m.temp_max_c {
        Some(t) => println!("  Akkutemperatur max   : {t:.1} C"),
        None => println!("  Akkutemperatur max   : nicht erfasst"),
    }
    match m.thermal_status_max {
        Some(t) => println!(
            "  Thermal-Status max   : {t} ({})",
            thermal::status_name(t)
        ),
        None => println!("  Thermal-Status max   : nicht erfasst"),
    }
    if m.synthetic {
        println!("  *** SYNTHETISCHE TESTDATEN — KEINE MESSUNG ***");
    }
    if m.valid {
        println!("  Gueltigkeit          : gueltig");
    } else {
        println!("  Gueltigkeit          : UNGUELTIG");
        for i in &m.issues {
            println!("      - {i}");
        }
    }
}

fn cmd_verdict(pos: &[String], args: &[String]) -> ExitCode {
    let root = match need_arg(pos, "<verzeichnis>") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Fehler: {e}");
            return ExitCode::from(3);
        }
    };
    let policy = policy_from(args);
    let (runs, errors) = verdict::collect_runs(&root, &policy);
    if runs.is_empty() {
        eprintln!("Fehler: keine verwertbaren *.csv unter {}", root.display());
        for e in errors {
            eprintln!("  - {e}");
        }
        return ExitCode::from(3);
    }
    let rep = verdict::build(runs, errors);

    println!("== S5-Auswertung (spec/phase0-spikeplan.md §2) ==");
    println!("Mindestdauer je Lauf: {:.1} h", policy.min_hours);
    if rep.any_synthetic {
        println!();
        println!("!!! ACHTUNG: mindestens eine Eingabedatei ist als SYNTHETISCH markiert.");
        println!("!!! Diese Ausgabe ist eine Werkzeugprobe, KEIN Messergebnis und");
        println!("!!! nicht Gate-tauglich.");
    }
    println!();

    for d in &rep.devices {
        println!("-- Geraet {} --", d.device);
        println!(
            "{:<4} {:<44} {:>3} {:>9} {:>8}",
            "Rh", "Beschreibung", "n", "Mittel", "SD"
        );
        for (id, desc) in verdict::SERIES.iter() {
            if let Some(s) = d.series.get(*id) {
                let m = s.mean.map(|v| format!("{v:8.2}")).unwrap_or("       -".into());
                let sd = s.sd.map(|v| format!("{v:7.2}")).unwrap_or("      -".into());
                println!("{:<4} {:<44} {:>3} {} {}", id, desc, s.values.len(), m, sd);
                for bad in &s.invalid_runs {
                    println!("      ! verworfen: {bad}");
                }
            }
        }
        println!();
        println!("  Zwischenschritte (Mittelwertdifferenzen, %/24 h):");
        for (label, v) in &d.deltas_info {
            println!("    {label:<32} {v:8.2}");
        }
        println!();
        println!("  Kriterien:");
        for c in &d.criteria {
            println!("    [{:<13}] {:<5} {}", c.decision.as_str(), c.id, c.text);
            if let Some(w) = &c.welch {
                println!(
                    "        Differenz {:.2} %/24 h, einseitiges 95-%-Intervall [{:.2}, {:.2}], df = {:.1}",
                    w.diff, w.lower95, w.upper95, w.df
                );
            }
            if !c.note.is_empty() {
                println!("        {}", c.note);
            }
            if let Some(n) = c.recommended_n {
                println!("        empfohlen: mindestens {n} gueltige Laeufe je Reihe wiederholen");
            }
        }
        println!();
        println!("  Geraeteurteil: {}", d.overall.as_str());
        println!();
    }

    if !rep.parse_errors.is_empty() {
        println!("Nicht eingelesen:");
        for e in &rep.parse_errors {
            println!("  - {e}");
        }
        println!();
    }
    println!("GESAMTURTEIL: {}", rep.overall.as_str());

    if rep.any_synthetic && !flag(args, "--allow-synthetic") {
        eprintln!();
        eprintln!("Abbruch: synthetische Daten. Mit --allow-synthetic erzwingen (nur fuer Werkzeugtests).");
        return ExitCode::from(3);
    }
    match rep.overall {
        Decision::Pass => ExitCode::from(0),
        Decision::Fail => ExitCode::from(1),
        _ => ExitCode::from(2),
    }
}

fn cmd_history(pos: &[String], args: &[String]) -> Result<(), String> {
    let path = need_arg(pos, "<history.txt>")?;
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let opts = history::Options {
        deltas: flag(args, "--deltas"),
        ..history::Options::default()
    };
    let rows = history::parse(&text, &opts)?;
    let mut meta: Vec<(String, String)> = Vec::new();
    if let Some(s) = opt(args, "--series") {
        meta.push(("series".into(), s));
    }
    if let Some(d) = opt(args, "--device") {
        meta.push(("device".into(), d));
    }
    let start = opt(args, "--start-unix")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0);
    let csv = history::to_csv(&rows, &meta, start);
    match opt(args, "--out") {
        Some(out) => {
            std::fs::write(Path::new(&out), &csv).map_err(|e| format!("{out}: {e}"))?;
            eprintln!("{} Zeilen geschrieben nach {out}", rows.len());
        }
        None => print!("{csv}"),
    }
    Ok(())
}

fn cmd_thermal(pos: &[String]) -> Result<(), String> {
    let path = need_arg(pos, "<thermal.txt>")?;
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let r = thermal::parse(&text);
    println!("Erkannt: {} Statuszeilen, {} Sensorzeilen", r.status_lines, r.sensor_lines);
    match r.status_max {
        Some(s) => println!("Hoechster Thermal-Status: {s} ({})", thermal::status_name(s)),
        None => println!("Hoechster Thermal-Status: nicht erkannt"),
    }
    if let Some(s) = r.sensor_status_max {
        println!("Hoechster Sensor-Status : {s} ({})", thermal::status_name(s));
    }
    if let Some((name, v)) = &r.hottest {
        println!("Waermster Sensor        : {name} = {v:.1} C");
    }
    match r.throttling_free() {
        Some(true) => println!("Kriterium 'kein Thermal-Throttling': BESTANDEN"),
        Some(false) => println!("Kriterium 'kein Thermal-Throttling': GERISSEN"),
        None => println!(
            "Kriterium 'kein Thermal-Throttling': KEINE DATEN — Dumpformat pruefen \
(dumpsys thermalservice)"
        ),
    }
    Ok(())
}

fn cmd_batterystats(pos: &[String], args: &[String]) -> Result<(), String> {
    let path = need_arg(pos, "<checkin.txt>")?;
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let r = batterystats::parse(&text);
    let top = opt(args, "--top").and_then(|v| v.parse::<usize>().ok()).unwrap_or(15);
    println!("Erkannte pwi/pws-Zeilen: {}", r.matched_lines);
    if r.matched_lines == 0 {
        println!("Keine bekannten Zeilen gefunden. Checkin-Format der Android-Version pruefen,");
        println!("ggf. `dumpsys batterystats --proto` verwenden. Ergebnis hier ist NICHT belastbar.");
        return Ok(());
    }
    if let Some(c) = r.battery_capacity_mah {
        println!("Akkukapazitaet laut System: {c:.0} mAh");
    }
    if let (Some(comp), Some(min), Some(max)) = (r.computed_drain_mah, r.min_drain_mah, r.max_drain_mah) {
        println!("Entnommen (berechnet/min/max): {comp:.1} / {min:.1} / {max:.1} mAh");
    }
    println!("Summe aller UID-Posten: {:.2} mAh", r.sum_label("uid"));
    println!();
    println!("{:<10} {:<16} {:>10}", "UID", "Posten", "mAh");
    for it in r.top(top) {
        let uid = if it.uid >= 0 { it.uid.to_string() } else { "-".into() };
        println!("{:<10} {:<16} {:>10.2}", uid, it.label, it.mah);
    }
    println!();
    println!("Hinweis: Diese Aufschluesselung ist informativ (Zuordnung des Verbrauchs),");
    println!("nicht Grundlage der Kriterien. Kriterien werden aus der Fuellstandskurve entschieden.");
    Ok(())
}
