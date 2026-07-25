//! Rekonstruktion der Fuellstandskurve aus `adb shell dumpsys batterystats --history`.
//!
//! Warum das der bevorzugte Weg ist: Das Geraet zeichnet die History selbst
//! auf. Es ist waehrend des Laufs **kein Polling ueber adb noetig**, das den
//! Prozessor aufwecken und damit die Messung selbst verfaelschen wuerde
//! (siehe MESSPROTOKOLL.md §5). Der Dump wird erst nach dem Lauf geholt.
//!
//! Erwartetes Format (AOSP `BatteryStats.HistoryPrinter`, Android 9-14):
//!
//! ```text
//! 0 (9) RESET:TIME: 2026-05-01-12-00-00
//!   +2m47s783ms (2) 099 status=discharging health=good plug=none temp=280 volt=4351 +running
//!   +1h04m12s000ms (1) 098 -running
//! ```
//!
//! Die Zeitangabe ist als **kumulativer Offset** seit dem History-Beginn
//! interpretiert. Ist die Ausgabe eines Geraets stattdessen inkrementell,
//! meldet der Parser das (nicht monotone Offsets) und `--deltas` schaltet um.
//!
//! **Formatstand:** nach AOSP-Quelle modelliert, gegen ein echtes Geraet
//! nicht verifiziert (kein Geraet vorhanden). Der Parser bricht bei
//! unplausibler Ausbeute ab, statt still Unsinn zu liefern.

/// Eine rekonstruierte Zeile.
#[derive(Debug, Clone)]
pub struct Row {
    pub t_rel_s: f64,
    pub level_pct: f64,
    pub voltage_uv: Option<f64>,
    pub temp_dc: Option<f64>,
    pub screen_on: Option<i64>,
    pub plugged: Option<i64>,
}

#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Zeitangaben als Inkremente statt als kumulative Offsets lesen.
    pub deltas: bool,
    /// Mindestzahl erkannter Fuellstandszeilen, sonst Fehler.
    pub min_rows: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            deltas: false,
            min_rows: 8,
        }
    }
}

/// `+1d02h03m04s567ms` -> Sekunden.
pub fn parse_duration(tok: &str) -> Option<f64> {
    let t = tok.strip_prefix('+').unwrap_or(tok);
    if t.is_empty() {
        return None;
    }
    let bytes: Vec<char> = t.chars().collect();
    let mut i = 0usize;
    let mut total = 0.0f64;
    let mut any = false;
    while i < bytes.len() {
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return None;
        }
        let num: f64 = bytes[start..i].iter().collect::<String>().parse().ok()?;
        let ustart = i;
        while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
            i += 1;
        }
        let unit: String = bytes[ustart..i].iter().collect();
        let factor = match unit.as_str() {
            "ms" => 0.001,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            "d" => 86400.0,
            _ => return None,
        };
        total += num * factor;
        any = true;
    }
    if any {
        Some(total)
    } else {
        None
    }
}

fn parse_kv<'a>(tokens: &'a [&'a str], key: &str) -> Option<&'a str> {
    tokens
        .iter()
        .find(|t| t.starts_with(key))
        .map(|t| &t[key.len()..])
}

/// History-Dump in Zeilen umsetzen.
pub fn parse(text: &str, opts: &Options) -> Result<Vec<Row>, String> {
    let mut rows: Vec<Row> = Vec::new();
    let mut cursor = 0.0f64;
    let mut screen: Option<i64> = None;
    let mut plugged: Option<i64> = None;
    let mut seen_lines = 0usize;

    for raw in text.lines() {
        let line = raw.trim();
        if !line.starts_with('+') {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }
        let dur = match parse_duration(tokens[0]) {
            Some(d) => d,
            None => continue,
        };
        seen_lines += 1;
        let t = if opts.deltas {
            cursor += dur;
            cursor
        } else {
            dur
        };

        for tok in &tokens[1..] {
            match *tok {
                "+screen" => screen = Some(1),
                "-screen" => screen = Some(0),
                _ => {}
            }
        }
        if let Some(p) = parse_kv(&tokens, "plug=") {
            plugged = Some(if p == "none" { 0 } else { 1 });
        }

        // Fuellstand: erstes Token nach einer optionalen "(N)"-Gruppe, das aus
        // genau drei Ziffern besteht.
        let level = tokens[1..]
            .iter()
            .find(|t| t.len() == 3 && t.chars().all(|c| c.is_ascii_digit()))
            .and_then(|t| t.parse::<f64>().ok())
            .filter(|v| *v <= 100.0);
        let level = match level {
            Some(l) => l,
            None => continue,
        };

        let temp = parse_kv(&tokens, "temp=").and_then(|v| v.parse::<f64>().ok());
        let volt = parse_kv(&tokens, "volt=")
            .and_then(|v| v.parse::<f64>().ok())
            .map(|mv| mv * 1000.0);

        rows.push(Row {
            t_rel_s: t,
            level_pct: level,
            voltage_uv: volt,
            temp_dc: temp,
            screen_on: screen,
            plugged,
        });
    }

    if rows.len() < opts.min_rows {
        return Err(format!(
            "nur {} verwertbare History-Zeilen erkannt (von {seen_lines} Kandidaten, Minimum {}). \
Format pruefen: `dumpsys batterystats --history | head -40` und ggf. --deltas verwenden.",
            rows.len(),
            opts.min_rows
        ));
    }
    if !opts.deltas && rows.windows(2).any(|w| w[1].t_rel_s < w[0].t_rel_s) {
        return Err(
            "Zeit-Offsets sind nicht monoton. Die Ausgabe ist vermutlich inkrementell -> \
mit --deltas erneut aufrufen."
                .to_string(),
        );
    }
    Ok(rows)
}

/// Zeilen in das Sample-CSV-Format schreiben.
pub fn to_csv(rows: &[Row], meta: &[(String, String)], start_unix: f64) -> String {
    let mut out = String::from("# s5-history v1\n# source=dumpsys batterystats --history\n");
    for (k, v) in meta {
        out.push_str(&format!("# {k}={v}\n"));
    }
    out.push_str("t_unix,level_pct,charge_uah,voltage_uv,temp_dc,thermal_status,screen_on,plugged\n");
    for r in rows {
        let fmt_opt = |v: Option<f64>| match v {
            Some(x) => format!("{x:.0}"),
            None => "-".to_string(),
        };
        let fmt_opt_i = |v: Option<i64>| match v {
            Some(x) => x.to_string(),
            None => "-".to_string(),
        };
        out.push_str(&format!(
            "{:.0},{:.0},-,{},{},-,{},{}\n",
            start_unix + r.t_rel_s,
            r.level_pct,
            fmt_opt(r.voltage_uv),
            fmt_opt(r.temp_dc),
            fmt_opt_i(r.screen_on),
            fmt_opt_i(r.plugged),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"Battery History (5% used, 12KB used of 320KB):
0 (9) RESET:TIME: 2026-05-01-12-00-00
  +1s241ms (2) 095 status=discharging health=good plug=none temp=280 volt=4331 -screen
  +2h47m00s000ms (2) 094 temp=281 volt=4310
  +5h30m00s000ms (2) 093 temp=280 volt=4300
  +8h10m00s000ms (2) 092 temp=279 volt=4290
  +10h50m00s000ms (2) 091 temp=280 volt=4280
  +13h30m00s000ms (2) 090 temp=280 volt=4270
  +16h10m00s000ms (2) 089 temp=281 volt=4260
  +18h50m00s000ms (2) 088 temp=280 volt=4250
  +21h30m00s000ms (2) 087 temp=280 volt=4240
  +23h59m00s000ms (2) 086 temp=280 volt=4230
"#;

    #[test]
    fn duration_parser() {
        assert!((parse_duration("+1s241ms").expect("d") - 1.241).abs() < 1e-9);
        assert!((parse_duration("+1d02h03m04s567ms").expect("d") - 93784.567).abs() < 1e-6);
        assert!((parse_duration("+2m47s783ms").expect("d") - 167.783).abs() < 1e-9);
        assert!(parse_duration("nonsense").is_none());
    }

    #[test]
    fn parses_history_into_rows() {
        let rows = parse(SAMPLE, &Options::default()).expect("parse");
        assert_eq!(rows.len(), 10);
        assert!((rows[0].level_pct - 95.0).abs() < 1e-9);
        assert_eq!(rows[0].plugged, Some(0));
        assert_eq!(rows[0].screen_on, Some(0));
        assert!((rows[9].t_rel_s - (23.0 * 3600.0 + 59.0 * 60.0)).abs() < 1e-6);
        let csv = to_csv(&rows, &[("series".into(), "R1".into())], 1_750_000_000.0);
        assert!(csv.contains("# series=R1"));
        assert!(csv.lines().count() >= 14);
    }

    #[test]
    fn too_few_rows_is_error() {
        let err = parse("  +1s241ms (2) 095 plug=none\n", &Options::default())
            .expect_err("muss fehlschlagen");
        assert!(err.contains("History-Zeilen"));
    }

    #[test]
    fn non_monotonic_offsets_are_reported() {
        let mut t = String::from("Battery History:\n");
        for (i, s) in [10, 20, 30, 5, 40, 50, 60, 70, 80].iter().enumerate() {
            t.push_str(&format!("  +{s}s (2) 0{:02} plug=none\n", 95 - i));
        }
        let err = parse(&t, &Options::default()).expect_err("muss fehlschlagen");
        assert!(err.contains("--deltas"));
    }

    #[test]
    fn deltas_mode_accumulates() {
        let mut t = String::from("Battery History:\n");
        for i in 0..10 {
            t.push_str(&format!("  +1h00m00s000ms (2) 0{:02} plug=none\n", 95 - i));
        }
        let rows = parse(
            &t,
            &Options {
                deltas: true,
                ..Options::default()
            },
        )
        .expect("parse");
        assert!((rows[9].t_rel_s - 36000.0).abs() < 1e-6);
    }
}
