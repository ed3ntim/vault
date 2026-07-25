//! Minimale Statistik fuer die S5-Auswertung. Nur `std`.
//!
//! Bewusst klein gehalten: lineare Regression (Entladerate), Stichproben-
//! Standardabweichung, Welch-Konfidenzintervall fuer die Differenz zweier
//! Messreihen und die daraus abgeleitete Mindest-Wiederholungszahl.

/// Arithmetisches Mittel. Leere Eingabe -> `None`.
pub fn mean(xs: &[f64]) -> Option<f64> {
    if xs.is_empty() {
        return None;
    }
    Some(xs.iter().sum::<f64>() / xs.len() as f64)
}

/// Stichproben-Standardabweichung (n-1). Braucht n >= 2.
pub fn sample_sd(xs: &[f64]) -> Option<f64> {
    if xs.len() < 2 {
        return None;
    }
    let m = mean(xs)?;
    let var = xs.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / (xs.len() as f64 - 1.0);
    Some(var.sqrt())
}

/// Tabelle der 0.95-Quantile der t-Verteilung (einseitig), df = 1..=30.
/// Standardwerte aus jeder Statistiktabelle; keine Messdaten.
const T95: [f64; 30] = [
    6.314, 2.920, 2.353, 2.132, 2.015, 1.943, 1.895, 1.860, 1.833, 1.812, 1.796, 1.782, 1.771,
    1.761, 1.753, 1.746, 1.740, 1.734, 1.729, 1.725, 1.721, 1.717, 1.714, 1.711, 1.708, 1.706,
    1.703, 1.701, 1.699, 1.697,
];

/// Einseitiges 95-%-Quantil der t-Verteilung, linear interpoliert.
pub fn t_quantile_95(df: f64) -> f64 {
    if !df.is_finite() || df <= 1.0 {
        return T95[0];
    }
    if df >= 120.0 {
        return 1.645;
    }
    if df >= 30.0 {
        // Interpolation zwischen df=30 (1.697) und df->inf (1.645)
        return 1.697 + (1.645 - 1.697) * ((df - 30.0) / 90.0);
    }
    let lo = df.floor();
    let hi = df.ceil();
    let a = T95[(lo as usize) - 1];
    if (hi - lo).abs() < f64::EPSILON {
        return a;
    }
    let b = T95[(hi as usize) - 1];
    a + (b - a) * (df - lo)
}

/// Ergebnis eines Welch-Vergleichs zweier unabhaengiger Messreihen.
#[derive(Debug, Clone, Copy)]
pub struct Welch {
    /// mean(a) - mean(b)
    pub diff: f64,
    pub se: f64,
    pub df: f64,
    pub t: f64,
    /// einseitige 95-%-Untergrenze der Differenz
    pub lower95: f64,
    /// einseitige 95-%-Obergrenze der Differenz
    pub upper95: f64,
}

/// Welch-Vergleich (ungleiche Varianzen, ungleiche n). Braucht je n >= 2.
pub fn welch(a: &[f64], b: &[f64]) -> Option<Welch> {
    let (na, nb) = (a.len() as f64, b.len() as f64);
    let sa = sample_sd(a)?;
    let sb = sample_sd(b)?;
    let va = sa * sa / na;
    let vb = sb * sb / nb;
    let se = (va + vb).sqrt();
    let denom = va * va / (na - 1.0) + vb * vb / (nb - 1.0);
    let df = if denom <= 0.0 {
        na + nb - 2.0
    } else {
        (va + vb) * (va + vb) / denom
    };
    let t = t_quantile_95(df);
    let diff = mean(a)? - mean(b)?;
    Some(Welch {
        diff,
        se,
        df,
        t,
        lower95: diff - t * se,
        upper95: diff + t * se,
    })
}

/// Kleinstes n (Laeufe **je** Messreihe), fuer das die halbe Breite des
/// einseitigen 95-%-Intervalls der Differenz <= `margin` bleibt, wenn beide
/// Reihen die Streuung `sd` haben. Obergrenze 30, dann `None`.
///
/// Grundlage: se = sd * sqrt(2/n), df = 2n-2.
pub fn required_n(sd: f64, margin: f64) -> Option<usize> {
    if margin <= 0.0 {
        return None;
    }
    if sd <= 0.0 {
        return Some(2);
    }
    for n in 2..=30usize {
        let nf = n as f64;
        let se = sd * (2.0 / nf).sqrt();
        if t_quantile_95(2.0 * nf - 2.0) * se <= margin {
            return Some(n);
        }
    }
    None
}

/// Lineare Regression y = a + b*x. Rueckgabe (b, a, r2).
pub fn regress(xs: &[f64], ys: &[f64]) -> Option<(f64, f64, f64)> {
    if xs.len() != ys.len() || xs.len() < 3 {
        return None;
    }
    let n = xs.len() as f64;
    let mx = mean(xs)?;
    let my = mean(ys)?;
    let mut sxx = 0.0;
    let mut sxy = 0.0;
    let mut syy = 0.0;
    for i in 0..xs.len() {
        let dx = xs[i] - mx;
        let dy = ys[i] - my;
        sxx += dx * dx;
        sxy += dx * dy;
        syy += dy * dy;
    }
    if sxx <= 0.0 {
        return None;
    }
    let b = sxy / sxx;
    let a = my - b * mx;
    let r2 = if syy <= 0.0 { 1.0 } else { (sxy * sxy) / (sxx * syy) };
    let _ = n;
    Some((b, a, r2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mean_and_sd() {
        let xs = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
        assert!((mean(&xs).expect("mean") - 5.0).abs() < 1e-12);
        // Stichproben-SD dieser Standardreihe: sqrt(32/7)
        let sd = sample_sd(&xs).expect("sd");
        assert!((sd - (32.0f64 / 7.0).sqrt()).abs() < 1e-12);
        assert!(sample_sd(&[1.0]).is_none());
        assert!(mean(&[]).is_none());
    }

    #[test]
    fn t_table_edges() {
        assert!((t_quantile_95(1.0) - 6.314).abs() < 1e-9);
        assert!((t_quantile_95(2.0) - 2.920).abs() < 1e-9);
        assert!((t_quantile_95(30.0) - 1.697).abs() < 1e-9);
        assert!((t_quantile_95(1000.0) - 1.645).abs() < 1e-9);
        // monoton fallend
        let mut prev = f64::INFINITY;
        let mut df = 1.0;
        while df < 200.0 {
            let t = t_quantile_95(df);
            assert!(t <= prev + 1e-12, "nicht monoton bei df={df}");
            prev = t;
            df += 0.5;
        }
    }

    #[test]
    fn welch_symmetric_case() {
        let a = [11.0, 11.4, 10.6];
        let b = [4.0, 4.2, 3.8];
        let w = welch(&a, &b).expect("welch");
        assert!((w.diff - 7.0).abs() < 1e-9);
        assert!(w.lower95 < w.diff && w.diff < w.upper95);
        // Streuung klein -> Obergrenze bleibt unter der 8-%-Schwelle
        assert!(w.upper95 < 8.0, "upper95={}", w.upper95);
    }

    #[test]
    fn welch_needs_two_values() {
        assert!(welch(&[1.0], &[1.0, 2.0]).is_none());
    }

    #[test]
    fn required_n_grows_with_sd() {
        let n_small = required_n(0.4, 1.0).expect("n");
        let n_big = required_n(2.0, 1.0).expect("n");
        assert!(n_big > n_small);
        assert!(required_n(50.0, 0.01).is_none());
    }

    #[test]
    fn regression_recovers_slope() {
        let xs: Vec<f64> = (0..50).map(|i| i as f64 * 0.5).collect();
        let ys: Vec<f64> = xs.iter().map(|x| 95.0 - 0.25 * x).collect();
        let (b, a, r2) = regress(&xs, &ys).expect("regress");
        assert!((b + 0.25).abs() < 1e-9);
        assert!((a - 95.0).abs() < 1e-9);
        assert!((r2 - 1.0).abs() < 1e-9);
    }
}
