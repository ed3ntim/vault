//! Minimale Statistik fuer die Messlaeufe. Keine Abhaengigkeiten.

use std::time::Duration;

/// Perzentil nach Nearest-Rank (kein Interpolieren — bei kleinen n ehrlicher).
pub fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil().max(1.0) as usize;
    sorted[rank.min(sorted.len()) - 1]
}

pub struct Summary {
    pub n: usize,
    pub min: Duration,
    pub p50: Duration,
    pub p95: Duration,
    pub max: Duration,
    pub mean: Duration,
}

pub fn summarize(mut v: Vec<Duration>) -> Summary {
    v.sort();
    let n = v.len();
    let sum: Duration = v.iter().sum();
    Summary {
        n,
        min: v.first().copied().unwrap_or_default(),
        p50: percentile(&v, 50.0),
        p95: percentile(&v, 95.0),
        max: v.last().copied().unwrap_or_default(),
        mean: if n == 0 {
            Duration::ZERO
        } else {
            sum / (n as u32)
        },
    }
}

/// Formatierung in Millisekunden mit drei Nachkommastellen.
pub fn ms(d: Duration) -> String {
    format!("{:.3} ms", d.as_secs_f64() * 1000.0)
}

/// Urteil gegen das Erfolgskriterium aus `spec/phase0-spikeplan.md` §3, S3:
/// „Revocation -> Verbindungsverlust des Revozierten in < 5 min (p95)".
pub const KRITERIUM_P95: Duration = Duration::from_secs(300);

pub fn urteil(p95: Duration) -> &'static str {
    if p95 < KRITERIUM_P95 {
        "unter 300 s"
    } else {
        "300 s oder mehr — Kriterium gerissen"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perzentil_nearest_rank() {
        let v: Vec<Duration> = (1..=100).map(|i| Duration::from_millis(i)).collect();
        assert_eq!(percentile(&v, 50.0), Duration::from_millis(50));
        assert_eq!(percentile(&v, 95.0), Duration::from_millis(95));
        assert_eq!(percentile(&v, 100.0), Duration::from_millis(100));
    }

    #[test]
    fn perzentil_leer() {
        assert_eq!(percentile(&[], 95.0), Duration::ZERO);
    }

    #[test]
    fn urteil_grenze() {
        assert_eq!(urteil(Duration::from_secs(299)), "unter 300 s");
        assert_eq!(
            urteil(Duration::from_secs(300)),
            "300 s oder mehr — Kriterium gerissen"
        );
    }
}
