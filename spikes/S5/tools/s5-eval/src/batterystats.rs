//! Zuordnung des Verbrauchs auf Subsysteme und UIDs aus
//! `adb shell dumpsys batterystats --checkin`.
//!
//! Dieser Teil liefert **keine** Gate-Entscheidung. Die Kriterien aus
//! `spec/phase0-spikeplan.md` §2 (S5) sind in %/24 h formuliert und werden aus
//! der Fuellstandskurve entschieden (`csvlog.rs`). Die Checkin-Auswertung sagt,
//! *wohin* der Strom geht -- das ist die Grundlage fuer die Fallback-Kaskade
//! (Shaping-Budget, Beacon-Intervall) und damit fuer GATE-3.
//!
//! Relevante Zeilen im Checkin-Format:
//!
//! ```text
//! 9,0,l,pws,3400,412,398,425          # battery capacity, computed, min/max drained (mAh)
//! 9,10145,l,pwi,uid,42.5              # Verbrauch je UID (mAh)
//! 9,0,l,pwi,screen,3.1                # Verbrauch je Subsystem (mAh)
//! ```
//!
//! **Formatstand:** Das Checkin-Format ist zwischen Android-Versionen nicht
//! stabil (Android 12+ bevorzugt `--proto`). Der Parser ist gegen synthetische
//! Beispiele nach der AOSP-Dokumentation getestet, **nicht** gegen ein echtes
//! Geraet. `s5-eval batterystats` gibt darum immer die Trefferzahl mit aus;
//! bei 0 Treffern ist das Format zu pruefen, nicht das Ergebnis zu glauben.

#[derive(Debug, Clone)]
pub struct PowerItem {
    pub uid: i64,
    pub label: String,
    pub mah: f64,
}

#[derive(Debug, Clone, Default)]
pub struct CheckinReport {
    pub battery_capacity_mah: Option<f64>,
    pub computed_drain_mah: Option<f64>,
    pub min_drain_mah: Option<f64>,
    pub max_drain_mah: Option<f64>,
    pub items: Vec<PowerItem>,
    pub matched_lines: usize,
}

impl CheckinReport {
    /// Posten absteigend nach mAh.
    pub fn top(&self, n: usize) -> Vec<&PowerItem> {
        let mut v: Vec<&PowerItem> = self.items.iter().collect();
        v.sort_by(|a, b| b.mah.partial_cmp(&a.mah).unwrap_or(std::cmp::Ordering::Equal));
        v.into_iter().take(n).collect()
    }

    /// Summe aller Posten mit passendem Label (z. B. "uid").
    pub fn sum_label(&self, label: &str) -> f64 {
        self.items
            .iter()
            .filter(|i| i.label == label)
            .map(|i| i.mah)
            .sum()
    }
}

pub fn parse(text: &str) -> CheckinReport {
    let mut rep = CheckinReport::default();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
        // Aufbau: <vers>,<uid>,<category>,<key>,...
        let key_idx = match f.iter().position(|x| *x == "pwi" || *x == "pws") {
            Some(i) if i >= 1 => i,
            _ => continue,
        };
        let uid = f.get(1).and_then(|v| v.parse::<i64>().ok()).unwrap_or(-1);
        match f[key_idx] {
            "pws" => {
                let nums: Vec<f64> = f[key_idx + 1..]
                    .iter()
                    .filter_map(|v| v.parse::<f64>().ok())
                    .collect();
                if !nums.is_empty() {
                    rep.matched_lines += 1;
                    rep.battery_capacity_mah = nums.first().copied();
                    rep.computed_drain_mah = nums.get(1).copied();
                    rep.min_drain_mah = nums.get(2).copied();
                    rep.max_drain_mah = nums.get(3).copied();
                }
            }
            "pwi" => {
                let label = match f.get(key_idx + 1) {
                    Some(l) => (*l).to_string(),
                    None => continue,
                };
                let mah = f[key_idx + 2..].iter().find_map(|v| v.parse::<f64>().ok());
                if let Some(mah) = mah {
                    rep.matched_lines += 1;
                    rep.items.push(PowerItem { uid, label, mah });
                }
            }
            _ => {}
        }
    }
    rep
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"9,0,i,vers,35,205,SP2A,SP2A
9,0,l,pws,3400,412.0,398.0,425.0
9,0,l,pwi,screen,3.1
9,0,l,pwi,idle,88.4
9,0,l,pwi,cell,12.0
9,0,l,pwi,bluetooth,9.5
9,10145,l,pwi,uid,42.5
9,10022,l,pwi,uid,7.25
9,0,l,foo,bar,1
"#;

    #[test]
    fn parses_summary_and_items() {
        let r = parse(SAMPLE);
        assert_eq!(r.battery_capacity_mah, Some(3400.0));
        assert_eq!(r.computed_drain_mah, Some(412.0));
        assert_eq!(r.max_drain_mah, Some(425.0));
        assert_eq!(r.items.len(), 6);
        assert_eq!(r.matched_lines, 7);
        let top = r.top(2);
        assert_eq!(top[0].label, "idle");
        assert!((top[1].mah - 42.5).abs() < 1e-9);
        assert!((r.sum_label("uid") - 49.75).abs() < 1e-9);
        assert_eq!(top[1].uid, 10145);
    }

    #[test]
    fn unknown_format_yields_zero_matches() {
        let r = parse("voellig anderes format\nnoch eine zeile\n");
        assert_eq!(r.matched_lines, 0);
        assert!(r.items.is_empty());
    }
}
