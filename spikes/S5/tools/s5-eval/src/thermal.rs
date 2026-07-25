//! Auswertung von `adb shell dumpsys thermalservice` fuer das S5-Kriterium
//! "Kein Thermal-Throttling" (`spec/phase0-spikeplan.md` §2, S5).
//!
//! Erwartet die Ausgabe eines oder mehrerer Dumps in einer Datei. Mehrere
//! Dumps werden von `s5-sample.sh` mit einer Markerzeile getrennt:
//!
//! ```text
//! ### sample t_unix=1750000000
//! IsStatusOverride: false
//! Thermal Status: 0
//! Current temperatures from HAL:
//! 	Temperature{mValue=29.6, mType=3, mName=VIRTUAL-SKIN, mStatus=0}
//! ```
//!
//! **Formatstand:** modelliert nach der dokumentierten AOSP-Ausgabe von
//! Android 10-14. Gegen ein echtes Geraet ist der Parser hier nicht
//! verifiziert worden (kein Geraet vorhanden); `s5-eval thermal --raw`
//! zeigt deshalb immer an, wie viele Zeilen erkannt wurden.

/// Android `PowerManager.THERMAL_STATUS_*`.
pub fn status_name(s: i64) -> &'static str {
    match s {
        0 => "NONE",
        1 => "LIGHT",
        2 => "MODERATE",
        3 => "SEVERE",
        4 => "CRITICAL",
        5 => "EMERGENCY",
        6 => "SHUTDOWN",
        _ => "UNBEKANNT",
    }
}

#[derive(Debug, Clone)]
pub struct SensorReading {
    pub name: String,
    pub value_c: f64,
    pub status: i64,
}

#[derive(Debug, Clone, Default)]
pub struct ThermalReport {
    /// Anzahl erkannter `Thermal Status:`-Zeilen.
    pub status_lines: usize,
    /// Anzahl erkannter `Temperature{...}`-Zeilen.
    pub sensor_lines: usize,
    /// Hoechster beobachteter globaler Thermal-Status.
    pub status_max: Option<i64>,
    /// Hoechster je Sensor beobachteter Status.
    pub sensor_status_max: Option<i64>,
    /// Waermster Sensorwert (Name, Grad Celsius).
    pub hottest: Option<(String, f64)>,
    pub readings: Vec<SensorReading>,
}

impl ThermalReport {
    /// Kriterium "kein Thermal-Throttling": alle Statuswerte == NONE (0).
    /// `None`, wenn nichts erkannt wurde (dann ist das Kriterium unentschieden).
    pub fn throttling_free(&self) -> Option<bool> {
        if self.status_lines == 0 && self.sensor_lines == 0 {
            return None;
        }
        let a = self.status_max.unwrap_or(0);
        let b = self.sensor_status_max.unwrap_or(0);
        Some(a == 0 && b == 0)
    }
}

fn value_after<'a>(hay: &'a str, key: &str) -> Option<&'a str> {
    let idx = hay.find(key)? + key.len();
    let rest = &hay[idx..];
    let end = rest
        .find(|c: char| c == ',' || c == '}' || c == ' ')
        .unwrap_or(rest.len());
    Some(rest[..end].trim())
}

/// Dump(s) auswerten.
pub fn parse(text: &str) -> ThermalReport {
    let mut rep = ThermalReport::default();
    for raw in text.lines() {
        let line = raw.trim();
        // globaler Status
        for key in ["Thermal Status:", "ThermalStatus:", "Status:"] {
            if let Some(rest) = line.strip_prefix(key) {
                if let Ok(v) = rest.trim().parse::<i64>() {
                    rep.status_lines += 1;
                    rep.status_max = Some(rep.status_max.map_or(v, |m: i64| m.max(v)));
                }
                break;
            }
        }
        // Sensorzeilen
        if line.contains("Temperature{") {
            let name = value_after(line, "mName=").unwrap_or("?").to_string();
            let value = value_after(line, "mValue=").and_then(|v| v.parse::<f64>().ok());
            let status = value_after(line, "mStatus=").and_then(|v| v.parse::<i64>().ok());
            if let (Some(value_c), Some(status)) = (value, status) {
                rep.sensor_lines += 1;
                rep.sensor_status_max =
                    Some(rep.sensor_status_max.map_or(status, |m: i64| m.max(status)));
                let better = rep
                    .hottest
                    .as_ref()
                    .map(|(_, v)| value_c > *v)
                    .unwrap_or(true);
                if better {
                    rep.hottest = Some((name.clone(), value_c));
                }
                rep.readings.push(SensorReading {
                    name,
                    value_c,
                    status,
                });
            }
        }
    }
    rep
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLEAN: &str = r#"### sample t_unix=1750000000
IsStatusOverride: false
Thermal Status: 0
Cached temperatures:
	Temperature{mValue=29.6, mType=3, mName=VIRTUAL-SKIN, mStatus=0}
Current temperatures from HAL:
	Temperature{mValue=31.2, mType=0, mName=CPU, mStatus=0}
### sample t_unix=1750000300
Thermal Status: 0
	Temperature{mValue=30.0, mType=3, mName=VIRTUAL-SKIN, mStatus=0}
"#;

    const THROTTLED: &str = r#"Thermal Status: 0
	Temperature{mValue=39.0, mType=3, mName=VIRTUAL-SKIN, mStatus=0}
### sample t_unix=1750003600
Thermal Status: 2
	Temperature{mValue=46.5, mType=3, mName=VIRTUAL-SKIN, mStatus=2}
"#;

    #[test]
    fn clean_dump_has_no_throttling() {
        let r = parse(CLEAN);
        assert_eq!(r.status_lines, 2);
        assert_eq!(r.sensor_lines, 3);
        assert_eq!(r.status_max, Some(0));
        assert_eq!(r.throttling_free(), Some(true));
        let (name, v) = r.hottest.clone().expect("hottest");
        assert_eq!(name, "CPU");
        assert!((v - 31.2).abs() < 1e-9);
    }

    #[test]
    fn throttling_is_detected() {
        let r = parse(THROTTLED);
        assert_eq!(r.status_max, Some(2));
        assert_eq!(r.sensor_status_max, Some(2));
        assert_eq!(r.throttling_free(), Some(false));
        assert_eq!(status_name(2), "MODERATE");
    }

    #[test]
    fn empty_input_is_undecided() {
        let r = parse("irgendwas ohne relevante Zeilen\n");
        assert_eq!(r.throttling_free(), None);
    }
}
