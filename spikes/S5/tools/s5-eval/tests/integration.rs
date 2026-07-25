//! Integrationstests gegen die SYNTHETISCHEN Beispieldaten in
//! `spikes/S5/tools/testdata/`.
//!
//! Diese Tests pruefen die Rechen- und Entscheidungslogik, **nicht** das
//! Verhalten eines Geraets. Es lagen bei Erstellung keine echten Rohdaten vor
//! (kein Android-Geraet in der Umgebung, siehe BERICHT.md §4).

use std::path::PathBuf;

use s5_eval::csvlog::{self, RunPolicy};
use s5_eval::verdict::{self, Decision};
use s5_eval::{batterystats, history, thermal};

fn testdata(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("testdata")
        .join(rel)
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(testdata(rel)).expect("Testdatei lesbar")
}

#[test]
fn verdict_over_synthetic_runs() {
    let root = testdata("synthetic-runs");
    let (runs, errors) = verdict::collect_runs(&root, &RunPolicy::default());
    assert!(errors.is_empty(), "Leseprobleme: {errors:?}");
    // 6 Reihen x 3 Laeufe + 1 absichtlich ungueltiger Lauf
    assert_eq!(runs.len(), 19, "unerwartete Laufzahl");
    assert!(runs.iter().all(|r| r.synthetic));

    let rep = verdict::build(runs, errors);
    assert!(rep.any_synthetic);
    assert_eq!(rep.devices.len(), 1);
    let d = &rep.devices[0];
    assert_eq!(d.device, "SYN-A");

    // Der Lauf mit eingeschaltetem Display muss verworfen worden sein.
    let r1 = d.series.get("R1").expect("R1");
    assert_eq!(r1.values.len(), 3);
    assert_eq!(r1.invalid_runs.len(), 1);
    assert!(r1.invalid_runs[0].contains("Display"));

    let by_id = |id: &str| {
        d.criteria
            .iter()
            .find(|c| c.id == id)
            .unwrap_or_else(|| panic!("Kriterium {id} fehlt"))
    };
    // Konstanten der Beispieldaten: R3-R0 = 7 (unter 8), R4-R3 = 4 (ueber 2).
    assert_eq!(by_id("K-A1").decision, Decision::Pass);
    assert_eq!(by_id("K-A2").decision, Decision::Fail);
    assert_eq!(by_id("K-B").decision, Decision::Fail);
    assert_eq!(by_id("K-C").decision, Decision::Pass);
    assert_eq!(d.overall, Decision::Fail);
    assert_eq!(rep.overall, Decision::Fail);
}

#[test]
fn single_run_metrics_match_generator_constant() {
    let path = testdata("synthetic-runs/R3/synthetic-R3-01.csv");
    let log = csvlog::parse_file(&path).expect("parse");
    let m = csvlog::evaluate(&log, &RunPolicy::default()).expect("eval");
    assert!(m.valid, "{:?}", m.issues);
    // Generatorkonstante 11.0 %/24 h, Quantisierung auf ganze Prozent
    assert!((m.drain_pct_per_24h - 11.0).abs() < 0.3, "{}", m.drain_pct_per_24h);
    assert!(m.hours >= 23.9);
    assert_eq!(m.device, "SYN-A");
}

#[test]
fn thermal_fixtures() {
    let clean = thermal::parse(&read("synthetic-thermalservice.txt"));
    assert_eq!(clean.status_lines, 3);
    assert_eq!(clean.throttling_free(), Some(true));
    assert_eq!(clean.status_max, Some(0));

    let bad = thermal::parse(&read("synthetic-thermalservice-throttled.txt"));
    assert_eq!(bad.throttling_free(), Some(false));
    assert_eq!(bad.status_max, Some(2));
}

#[test]
fn checkin_fixture() {
    let r = batterystats::parse(&read("synthetic-batterystats-checkin.txt"));
    assert!(r.matched_lines >= 9);
    assert_eq!(r.battery_capacity_mah, Some(4000.0));
    assert!((r.sum_label("uid") - 140.70).abs() < 1e-6);
    let top = r.top(1);
    assert_eq!(top[0].label, "idle");
}

#[test]
fn history_fixture_round_trips_into_csv() {
    let rows = history::parse(&read("synthetic-batterystats-history.txt"), &history::Options::default())
        .expect("history parse");
    assert_eq!(rows.len(), 12);
    let csv = history::to_csv(
        &rows,
        &[
            ("series".to_string(), "R1".to_string()),
            ("device".to_string(), "SYN-A".to_string()),
            ("synthetic".to_string(), "true".to_string()),
        ],
        1_750_000_000.0,
    );
    let log = csvlog::parse_str(&csv, &testdata("history-roundtrip.csv")).expect("csv parse");
    let m = csvlog::evaluate(&log, &RunPolicy::default()).expect("eval");
    assert!(m.valid, "{:?}", m.issues);
    // 95 % -> 84 % in knapp 24 h == 11 Prozentpunkte
    assert!((m.drain_pct_per_24h - 11.0).abs() < 0.5, "{}", m.drain_pct_per_24h);
    assert!(m.synthetic);
}
