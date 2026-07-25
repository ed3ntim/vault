//! Einlesen und Bewerten eines einzelnen Messlaufs (Sample-CSV).
//!
//! Format (von `tools/collect/s5-sample.sh` bzw. `s5-eval history` erzeugt):
//!
//! ```text
//! # s5-sample v1
//! # series=R3
//! # device=DEV-A
//! # design_capacity_uah=4000000
//! t_unix,level_pct,charge_uah,voltage_uv,temp_dc,thermal_status,screen_on,plugged
//! 1750000000,95,3800000,4180000,300,0,0,0
//! ```
//!
//! Pflichtspalten: `t_unix`, `level_pct`. Alles andere ist optional und wird,
//! wenn vorhanden, fuer Gueltigkeitspruefungen benutzt.

use crate::stats;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Ein Messpunkt.
#[derive(Debug, Clone)]
pub struct Sample {
    pub t_unix: f64,
    pub level_pct: f64,
    pub charge_uah: Option<f64>,
    pub temp_dc: Option<f64>,
    pub thermal_status: Option<i64>,
    pub screen_on: Option<i64>,
    pub plugged: Option<i64>,
}

/// Ein eingelesener Lauf inklusive Kopf-Metadaten.
#[derive(Debug, Clone)]
pub struct RunLog {
    pub path: PathBuf,
    pub meta: BTreeMap<String, String>,
    pub samples: Vec<Sample>,
}

impl RunLog {
    pub fn meta_get(&self, key: &str) -> Option<&str> {
        self.meta.get(key).map(|s| s.as_str())
    }

    /// Datei ist als synthetisch markiert (`# synthetic=true`) oder heisst so.
    pub fn is_synthetic(&self) -> bool {
        if self.meta_get("synthetic").map(|v| v == "true").unwrap_or(false) {
            return true;
        }
        self.path
            .file_name()
            .and_then(|f| f.to_str())
            .map(|f| f.starts_with("synthetic-"))
            .unwrap_or(false)
    }
}

/// Grenzwerte fuer die Gueltigkeitspruefung eines Laufs.
#[derive(Debug, Clone, Copy)]
pub struct RunPolicy {
    /// Mindestdauer in Stunden (Gate-Lauf: 20; Screening: kleiner, dann kein Gate).
    pub min_hours: f64,
    /// Hoechster zulaessiger Startfuellstand.
    pub max_start_level: f64,
    /// Niedrigster zulaessiger Startfuellstand.
    pub min_start_level: f64,
    /// Fuellstand, den ein Lauf nicht unterschreiten darf (Nichtlinearitaet,
    /// Battery-Saver-Schwellen bei 20 %/15 %).
    pub min_end_level: f64,
    /// Mindestzahl Messpunkte.
    pub min_samples: usize,
    /// Mindest-Bestimmtheitsmass der Entladegeraden.
    pub min_r2: f64,
}

impl Default for RunPolicy {
    fn default() -> Self {
        // Werte aus MESSPROTOKOLL.md §4 (Randbedingungen). Keine Messwerte,
        // sondern Durchfuehrungsgrenzen.
        RunPolicy {
            min_hours: 20.0,
            max_start_level: 97.0,
            min_start_level: 88.0,
            min_end_level: 25.0,
            min_samples: 8,
            min_r2: 0.90,
        }
    }
}

/// Kennzahlen eines Laufs.
#[derive(Debug, Clone)]
pub struct RunMetrics {
    pub id: String,
    pub series: String,
    pub device: String,
    pub hours: f64,
    pub level_start: f64,
    pub level_end: f64,
    pub n_samples: usize,
    /// Entladerate in Prozentpunkten pro 24 h (aus linearer Regression).
    pub drain_pct_per_24h: f64,
    pub r2: f64,
    /// Entladerate aus dem Coulomb-Counter, falls Spalte vorhanden (mAh/24 h).
    pub drain_mah_per_24h: Option<f64>,
    /// Coulomb-Rate, umgerechnet auf %/24 h ueber `design_capacity_uah`.
    pub drain_pct_per_24h_coulomb: Option<f64>,
    pub temp_max_c: Option<f64>,
    pub thermal_status_max: Option<i64>,
    /// Lauf war kuerzer als 24 h -> Rate ist hochgerechnet.
    pub extrapolated: bool,
    pub synthetic: bool,
    pub valid: bool,
    pub issues: Vec<String>,
}

fn parse_f64(s: &str) -> Option<f64> {
    let s = s.trim();
    if s.is_empty() || s == "-" || s.eq_ignore_ascii_case("na") {
        return None;
    }
    s.parse::<f64>().ok()
}

fn parse_i64(s: &str) -> Option<i64> {
    parse_f64(s).map(|v| v as i64)
}

/// Sample-CSV einlesen.
pub fn parse_file(path: &Path) -> Result<RunLog, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("{}: nicht lesbar: {e}", path.display()))?;
    parse_str(&text, path)
}

/// Sample-CSV aus einem String einlesen (fuer Tests).
pub fn parse_str(text: &str, path: &Path) -> Result<RunLog, String> {
    let mut meta: BTreeMap<String, String> = BTreeMap::new();
    let mut header: Option<Vec<String>> = None;
    let mut samples: Vec<Sample> = Vec::new();

    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix('#') {
            if let Some((k, v)) = rest.split_once('=') {
                meta.insert(k.trim().to_string(), v.trim().to_string());
            }
            continue;
        }
        let cols: Vec<&str> = line.split(',').map(|c| c.trim()).collect();
        match &header {
            None => {
                let cols: Vec<String> = cols.iter().map(|c| c.to_lowercase()).collect();
                if !cols.iter().any(|c| c == "t_unix") || !cols.iter().any(|c| c == "level_pct") {
                    return Err(format!(
                        "{}: Kopfzeile ohne Pflichtspalten t_unix/level_pct (Zeile {})",
                        path.display(),
                        lineno + 1
                    ));
                }
                header = Some(cols);
            }
            Some(h) => {
                let get = |name: &str| -> Option<&str> {
                    h.iter().position(|c| c == name).and_then(|i| cols.get(i).copied())
                };
                let t_unix = match get("t_unix").and_then(parse_f64) {
                    Some(v) => v,
                    None => continue, // unvollstaendige Zeile ueberspringen
                };
                let level = match get("level_pct").and_then(parse_f64) {
                    Some(v) => v,
                    None => continue,
                };
                samples.push(Sample {
                    t_unix,
                    level_pct: level,
                    charge_uah: get("charge_uah").and_then(parse_f64),
                    temp_dc: get("temp_dc").and_then(parse_f64),
                    thermal_status: get("thermal_status").and_then(parse_i64),
                    screen_on: get("screen_on").and_then(parse_i64),
                    plugged: get("plugged").and_then(parse_i64),
                });
            }
        }
    }

    if header.is_none() {
        return Err(format!("{}: keine Kopfzeile gefunden", path.display()));
    }
    samples.sort_by(|a, b| a.t_unix.partial_cmp(&b.t_unix).unwrap_or(std::cmp::Ordering::Equal));
    Ok(RunLog {
        path: path.to_path_buf(),
        meta,
        samples,
    })
}

/// Kennzahlen und Gueltigkeit eines Laufs berechnen.
pub fn evaluate(run: &RunLog, policy: &RunPolicy) -> Result<RunMetrics, String> {
    let mut issues: Vec<String> = Vec::new();
    let n = run.samples.len();
    if n < 3 {
        return Err(format!("{}: weniger als 3 Messpunkte", run.path.display()));
    }

    let t0 = run.samples[0].t_unix;
    let hours: Vec<f64> = run.samples.iter().map(|s| (s.t_unix - t0) / 3600.0).collect();
    let levels: Vec<f64> = run.samples.iter().map(|s| s.level_pct).collect();
    let duration_h = hours[n - 1];

    let (slope, _intercept, r2) = stats::regress(&hours, &levels)
        .ok_or_else(|| format!("{}: Regression nicht moeglich", run.path.display()))?;
    let drain = -slope * 24.0;

    // Coulomb-Counter, falls vollstaendig vorhanden
    let charges: Vec<f64> = run.samples.iter().filter_map(|s| s.charge_uah).collect();
    let (drain_mah, drain_pct_coulomb) = if charges.len() == n {
        let (cs, _, _) = stats::regress(&hours, &charges).unwrap_or((0.0, 0.0, 0.0));
        let mah = -cs * 24.0 / 1000.0;
        let pct = run
            .meta_get("design_capacity_uah")
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|c| *c > 0.0)
            .map(|cap| -cs * 24.0 / cap * 100.0);
        (Some(mah), pct)
    } else {
        if !charges.is_empty() {
            issues.push("charge_uah nur teilweise vorhanden -> Coulomb-Auswertung entfaellt".into());
        }
        (None, None)
    };

    let temp_max_c = run
        .samples
        .iter()
        .filter_map(|s| s.temp_dc)
        .fold(None::<f64>, |acc, v| Some(acc.map_or(v, |a: f64| a.max(v))))
        .map(|dc| dc / 10.0);
    let thermal_max = run
        .samples
        .iter()
        .filter_map(|s| s.thermal_status)
        .fold(None::<i64>, |acc, v| Some(acc.map_or(v, |a: i64| a.max(v))));

    // --- Gueltigkeitspruefungen ---
    if run.samples.iter().any(|s| s.plugged == Some(1)) {
        issues.push("Geraet war waehrend des Laufs am Ladegeraet (plugged=1)".into());
    }
    if run.samples.iter().any(|s| s.screen_on == Some(1)) {
        issues.push("Display war waehrend des Laufs an (screen_on=1)".into());
    }
    if n < policy.min_samples {
        issues.push(format!("nur {n} Messpunkte (< {})", policy.min_samples));
    }
    if duration_h < policy.min_hours {
        issues.push(format!(
            "Laufdauer {duration_h:.2} h < Mindestdauer {:.2} h",
            policy.min_hours
        ));
    }
    let level_start = levels[0];
    let level_end = levels[n - 1];
    if level_start > policy.max_start_level || level_start < policy.min_start_level {
        issues.push(format!(
            "Startfuellstand {level_start:.0} % ausserhalb [{:.0}, {:.0}]",
            policy.min_start_level, policy.max_start_level
        ));
    }
    if level_end < policy.min_end_level {
        issues.push(format!(
            "Endfuellstand {level_end:.0} % unter Mindestwert {:.0} %",
            policy.min_end_level
        ));
    }
    if r2 < policy.min_r2 {
        issues.push(format!(
            "Entladekurve nicht hinreichend linear (r2 = {r2:.3} < {:.2})",
            policy.min_r2
        ));
    }
    if levels.windows(2).any(|w| w[1] > w[0] + 0.5) {
        issues.push("Fuellstand steigt zwischendurch -> Ladevorgang oder Fuellstandssprung".into());
    }

    let id = run
        .path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("?")
        .to_string();
    let series = run
        .meta_get("series")
        .map(|s| s.to_string())
        .or_else(|| {
            run.path
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|s| s.to_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "?".to_string());
    let device = run.meta_get("device").unwrap_or("?").to_string();

    Ok(RunMetrics {
        id,
        series,
        device,
        hours: duration_h,
        level_start,
        level_end,
        n_samples: n,
        drain_pct_per_24h: drain,
        r2,
        drain_mah_per_24h: drain_mah,
        drain_pct_per_24h_coulomb: drain_pct_coulomb,
        temp_max_c,
        thermal_status_max: thermal_max,
        extrapolated: duration_h < 23.5,
        synthetic: run.is_synthetic(),
        valid: issues.is_empty(),
        issues,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synth(drain_per_24h: f64, hours: f64, step_min: f64) -> String {
        let mut s = String::from("# s5-sample v1\n# synthetic=true\n# series=RT\n# device=DEV-T\n# design_capacity_uah=4000000\nt_unix,level_pct,charge_uah,voltage_uv,temp_dc,thermal_status,screen_on,plugged\n");
        let steps = (hours * 60.0 / step_min) as i64;
        for i in 0..=steps {
            let h = i as f64 * step_min / 60.0;
            let exact = 95.0 - drain_per_24h * h / 24.0;
            let charge = 4_000_000.0 * exact / 100.0;
            s.push_str(&format!(
                "{},{},{:.0},4180000,300,0,0,0\n",
                1_750_000_000i64 + (h * 3600.0) as i64,
                exact.floor() as i64,
                charge
            ));
        }
        s
    }

    #[test]
    fn parses_and_recovers_drain_rate() {
        let text = synth(11.0, 24.0, 15.0);
        let run = parse_str(&text, Path::new("synthetic-RT-01.csv")).expect("parse");
        assert!(run.is_synthetic());
        assert_eq!(run.meta_get("series"), Some("RT"));
        let m = evaluate(&run, &RunPolicy::default()).expect("eval");
        assert!(m.valid, "issues: {:?}", m.issues);
        assert!(
            (m.drain_pct_per_24h - 11.0).abs() < 0.3,
            "drain={}",
            m.drain_pct_per_24h
        );
        let c = m.drain_pct_per_24h_coulomb.expect("coulomb");
        assert!((c - 11.0).abs() < 0.01, "coulomb={c}");
        assert!(!m.extrapolated);
        assert_eq!(m.thermal_status_max, Some(0));
    }

    #[test]
    fn short_run_is_invalid_and_marked_extrapolated() {
        let text = synth(11.0, 6.0, 15.0);
        let run = parse_str(&text, Path::new("synthetic-RT-02.csv")).expect("parse");
        let m = evaluate(&run, &RunPolicy::default()).expect("eval");
        assert!(!m.valid);
        assert!(m.extrapolated);
        assert!(m.issues.iter().any(|i| i.contains("Mindestdauer")));
    }

    #[test]
    fn charging_and_screen_on_invalidate() {
        let mut text = synth(11.0, 24.0, 15.0);
        text.push_str("1750086500,80,3200000,4180000,300,0,1,1\n");
        let run = parse_str(&text, Path::new("synthetic-RT-03.csv")).expect("parse");
        let m = evaluate(&run, &RunPolicy::default()).expect("eval");
        assert!(!m.valid);
        assert!(m.issues.iter().any(|i| i.contains("Ladegeraet")));
        assert!(m.issues.iter().any(|i| i.contains("Display")));
    }

    #[test]
    fn missing_required_column_is_error() {
        let text = "# x=1\nt_unix,foo\n1,2\n";
        assert!(parse_str(text, Path::new("x.csv")).is_err());
    }
}
