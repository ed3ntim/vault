//! Zusammenfuehrung der Einzellaeufe zu den Erfolgskriterien aus
//! `spec/phase0-spikeplan.md` §2 (S5):
//!
//! > - Zusatzverbrauch < 8 %/24 h im Leerlauf-Betrieb
//! > - BLE-Beacons < 2 %/24 h zusaetzlich
//! > - Kein Thermal-Throttling
//!
//! Zwei Dinge macht dieses Modul bewusst **nicht**:
//!
//! 1. Es entscheidet die Auslegungsfrage nicht, worauf sich "Zusatzverbrauch"
//!    bezieht (Netzprofil ohne Mesh oder alles inklusive BLE). Beide Lesarten
//!    werden als K-A1 und K-A2 getrennt ausgewiesen. Die Aufloesung gehoert in
//!    den ADR zu GATE-3, nicht in ein Werkzeug.
//! 2. Es mittelt nicht ueber Geraetemodelle. %/24 h ist geraeteabhaengig
//!    (Akkukapazitaet); jede Auswertung erfolgt je Geraet, das Gesamturteil ist
//!    der schlechteste Einzelfall.

use crate::csvlog::{self, RunMetrics, RunPolicy};
use crate::stats::{self, Welch};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const SERIES: [(&str, &str); 8] = [
    ("R0", "Baseline: Geraet idle, Vault nicht aktiv"),
    ("R1", "nur Onion (Foreground-Service, Client-Auth)"),
    ("R2", "+ Snowflake/meek"),
    ("R3", "+ Traffic-Shaping"),
    ("R4", "+ BLE-Beacons (30 s)"),
    ("R5", "Referenz-Messenger"),
    ("K1", "Kontrolle: Flugmodus, Vault gestoppt"),
    ("K2", "Kontrolle: Flugmodus, Vault aktiv"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Pass,
    Fail,
    Inconclusive,
    NoData,
}

impl Decision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::Pass => "BESTANDEN",
            Decision::Fail => "GERISSEN",
            Decision::Inconclusive => "UNENTSCHIEDEN",
            Decision::NoData => "KEINE DATEN",
        }
    }
    fn rank(&self) -> u8 {
        match self {
            Decision::Pass => 0,
            Decision::Inconclusive => 1,
            Decision::NoData => 2,
            Decision::Fail => 3,
        }
    }
}

/// Entscheidungsregel: nur wenn das ganze einseitige 95-%-Intervall unter der
/// Schwelle liegt, gilt das Kriterium als erfuellt. Liegt es ganz darueber, ist
/// es gerissen. Alles andere ist unentschieden -> mehr Wiederholungen.
pub fn decide(w: &Welch, threshold: f64) -> Decision {
    if w.upper95 < threshold {
        Decision::Pass
    } else if w.lower95 > threshold {
        Decision::Fail
    } else {
        Decision::Inconclusive
    }
}

#[derive(Debug, Clone)]
pub struct SeriesAgg {
    pub series: String,
    pub values: Vec<f64>,
    pub mean: Option<f64>,
    pub sd: Option<f64>,
    pub invalid_runs: Vec<String>,
    pub thermal_status_max: Option<i64>,
    pub temp_max_c: Option<f64>,
    pub any_synthetic: bool,
}

#[derive(Debug, Clone)]
pub struct Criterion {
    pub id: String,
    pub text: String,
    pub threshold: f64,
    pub welch: Option<Welch>,
    pub decision: Decision,
    pub note: String,
    /// Empfohlene Laufzahl je Reihe, falls unentschieden.
    pub recommended_n: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct DeviceVerdict {
    pub device: String,
    pub series: BTreeMap<String, SeriesAgg>,
    pub criteria: Vec<Criterion>,
    pub deltas_info: Vec<(String, f64)>,
    pub overall: Decision,
}

#[derive(Debug, Clone)]
pub struct Report {
    pub runs: Vec<RunMetrics>,
    pub devices: Vec<DeviceVerdict>,
    pub parse_errors: Vec<String>,
    pub any_synthetic: bool,
    pub overall: Decision,
}

/// Alle `*.csv` unterhalb von `root` einlesen (Reihe aus `# series=` oder aus
/// dem Verzeichnisnamen).
pub fn collect_runs(root: &Path, policy: &RunPolicy) -> (Vec<RunMetrics>, Vec<String>) {
    let mut files: Vec<PathBuf> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    walk(root, &mut files, &mut errors);
    files.sort();
    let mut runs = Vec::new();
    for f in files {
        match csvlog::parse_file(&f).and_then(|r| csvlog::evaluate(&r, policy)) {
            Ok(m) => runs.push(m),
            Err(e) => errors.push(e),
        }
    }
    (runs, errors)
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>, errors: &mut Vec<String>) {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            errors.push(format!("{}: {e}", dir.display()));
            return;
        }
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            walk(&p, out, errors);
        } else if p.extension().and_then(|e| e.to_str()) == Some("csv") {
            out.push(p);
        }
    }
}

fn aggregate(runs: &[RunMetrics], device: &str, series: &str) -> SeriesAgg {
    let mut values = Vec::new();
    let mut invalid = Vec::new();
    let mut thermal: Option<i64> = None;
    let mut temp: Option<f64> = None;
    let mut synthetic = false;
    for r in runs.iter().filter(|r| r.device == device && r.series == series) {
        if let Some(t) = r.thermal_status_max {
            thermal = Some(thermal.map_or(t, |m: i64| m.max(t)));
        }
        if let Some(t) = r.temp_max_c {
            temp = Some(temp.map_or(t, |m: f64| m.max(t)));
        }
        synthetic |= r.synthetic;
        if r.valid {
            values.push(r.drain_pct_per_24h);
        } else {
            invalid.push(format!("{} ({})", r.id, r.issues.join("; ")));
        }
    }
    SeriesAgg {
        series: series.to_string(),
        mean: stats::mean(&values),
        sd: stats::sample_sd(&values),
        values,
        invalid_runs: invalid,
        thermal_status_max: thermal,
        temp_max_c: temp,
        any_synthetic: synthetic,
    }
}

fn criterion(
    id: &str,
    text: &str,
    a: &SeriesAgg,
    b: &SeriesAgg,
    threshold: f64,
) -> Criterion {
    let mut note = String::new();
    let (welch, decision, rec) = match stats::welch(&a.values, &b.values) {
        Some(w) => {
            let d = decide(&w, threshold);
            let rec = if d == Decision::Inconclusive {
                let pooled = ((a.sd.unwrap_or(0.0).powi(2) + b.sd.unwrap_or(0.0).powi(2)) / 2.0).sqrt();
                let margin = (threshold - w.diff).abs().max(0.1);
                stats::required_n(pooled, margin)
            } else {
                None
            };
            (Some(w), d, rec)
        }
        None => {
            note = format!(
                "zu wenige gueltige Laeufe: {}={}, {}={} (mindestens je 2)",
                a.series,
                a.values.len(),
                b.series,
                b.values.len()
            );
            (None, Decision::NoData, None)
        }
    };
    Criterion {
        id: id.to_string(),
        text: text.to_string(),
        threshold,
        welch,
        decision,
        note,
        recommended_n: rec,
    }
}

pub fn build(runs: Vec<RunMetrics>, parse_errors: Vec<String>) -> Report {
    let mut devices: Vec<String> = runs.iter().map(|r| r.device.clone()).collect();
    devices.sort();
    devices.dedup();

    let mut out: Vec<DeviceVerdict> = Vec::new();
    let any_synthetic = runs.iter().any(|r| r.synthetic);

    for dev in devices {
        let mut map: BTreeMap<String, SeriesAgg> = BTreeMap::new();
        for (s, _) in SERIES.iter() {
            map.insert((*s).to_string(), aggregate(&runs, &dev, s));
        }
        let get = |k: &str| map.get(k).cloned().unwrap_or_else(|| SeriesAgg {
            series: k.to_string(),
            values: vec![],
            mean: None,
            sd: None,
            invalid_runs: vec![],
            thermal_status_max: None,
            temp_max_c: None,
            any_synthetic: false,
        });

        let (r0, r3, r4) = (get("R0"), get("R3"), get("R4"));
        let mut criteria = vec![
            criterion(
                "K-A1",
                "Zusatzverbrauch Netzprofil ohne Mesh (R3 - R0) < 8 %/24 h",
                &r3,
                &r0,
                8.0,
            ),
            criterion(
                "K-A2",
                "Zusatzverbrauch inkl. BLE (R4 - R0) < 8 %/24 h [zweite Lesart]",
                &r4,
                &r0,
                8.0,
            ),
            criterion(
                "K-B",
                "BLE-Beacons zusaetzlich (R4 - R3) < 2 %/24 h",
                &r4,
                &r3,
                2.0,
            ),
        ];

        // K-C: Thermal. Bewertet werden die Reihen, in denen Vault laeuft;
        // R0/R5 dienen nur der Umgebungskontrolle.
        let thermal_vals: Vec<i64> = map
            .iter()
            .filter(|(k, _)| matches!(k.as_str(), "R1" | "R2" | "R3" | "R4" | "K2"))
            .filter_map(|(_, s)| s.thermal_status_max)
            .collect();
        let (tdec, tnote) = if thermal_vals.is_empty() {
            (
                Decision::NoData,
                "keine thermal_status-Spalte in den Sample-Dateien; \
`s5-eval thermal <dump>` separat auswerten"
                    .to_string(),
            )
        } else {
            let max = thermal_vals.iter().copied().max().unwrap_or(0);
            if max == 0 {
                (Decision::Pass, "alle Laeufe THERMAL_STATUS_NONE".to_string())
            } else {
                (
                    Decision::Fail,
                    format!("hoechster Thermal-Status {max} ({})", crate::thermal::status_name(max)),
                )
            }
        };
        criteria.push(Criterion {
            id: "K-C".into(),
            text: "Kein Thermal-Throttling in allen Reihen".into(),
            threshold: 0.0,
            welch: None,
            decision: tdec,
            note: tnote,
            recommended_n: None,
        });

        // Informative Zwischenschritte fuer GATE-3
        let mut deltas_info = Vec::new();
        let pairs = [
            ("R1-R0 (Onion allein)", "R1", "R0"),
            ("R2-R1 (Snowflake)", "R2", "R1"),
            ("R3-R2 (Shaping)", "R3", "R2"),
            ("R4-R3 (BLE 30 s)", "R4", "R3"),
            ("R5-R0 (Referenz-Messenger)", "R5", "R0"),
        ];
        for (label, a, b) in pairs {
            let (aa, bb) = (get(a), get(b));
            if let (Some(ma), Some(mb)) = (aa.mean, bb.mean) {
                deltas_info.push((label.to_string(), ma - mb));
            }
        }

        let dev_overall = criteria
            .iter()
            .map(|c| c.decision)
            .max_by_key(|d| d.rank())
            .unwrap_or(Decision::NoData);
        out.push(DeviceVerdict {
            device: dev,
            series: map,
            criteria,
            deltas_info,
            overall: dev_overall,
        });
    }

    // Gesamturteil = schlechtester Einzelfall ueber alle Geraete.
    let overall = out
        .iter()
        .map(|d| d.overall)
        .max_by_key(|d| d.rank())
        .unwrap_or(Decision::NoData);

    Report {
        runs,
        devices: out,
        parse_errors,
        any_synthetic,
        overall,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agg(series: &str, vals: &[f64]) -> SeriesAgg {
        SeriesAgg {
            series: series.into(),
            values: vals.to_vec(),
            mean: stats::mean(vals),
            sd: stats::sample_sd(vals),
            invalid_runs: vec![],
            thermal_status_max: Some(0),
            temp_max_c: Some(31.0),
            any_synthetic: true,
        }
    }

    #[test]
    fn pass_fail_inconclusive_branches() {
        // klar unter der Schwelle
        let c = criterion("X", "t", &agg("R3", &[11.0, 11.4, 10.6]), &agg("R0", &[4.0, 4.2, 3.8]), 8.0);
        assert_eq!(c.decision, Decision::Pass);
        // klar darueber
        let c = criterion("X", "t", &agg("R4", &[15.0, 15.4, 14.6]), &agg("R3", &[11.0, 11.4, 10.6]), 2.0);
        assert_eq!(c.decision, Decision::Fail);
        // Differenz nahe der Schwelle -> unentschieden, mit Empfehlung
        let c = criterion("X", "t", &agg("R4", &[13.6, 14.0, 13.2]), &agg("R3", &[11.0, 11.4, 10.6]), 2.0);
        assert_eq!(c.decision, Decision::Inconclusive);
        assert!(c.recommended_n.unwrap_or(0) >= 3);
    }

    #[test]
    fn single_run_gives_no_data() {
        let c = criterion("X", "t", &agg("R3", &[11.0]), &agg("R0", &[4.0]), 8.0);
        assert_eq!(c.decision, Decision::NoData);
        assert!(c.note.contains("mindestens je 2"));
    }

    #[test]
    fn decision_ranking_worst_wins() {
        let worst = [Decision::Pass, Decision::Inconclusive, Decision::Fail]
            .into_iter()
            .max_by_key(|d| d.rank());
        assert_eq!(worst, Some(Decision::Fail));
    }
}
