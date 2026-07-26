//! `H(x)` — BLAKE3-256.
//!
//! Normativ: `spec/protokoll-spec.md` §1 („`H(x)` — BLAKE3-256"). Verwendet
//! u. a. für `contact_id = H(ik_ed_pub_of_contact)` (§3),
//! `msg_id = H(dr_header ‖ ciphertext)` (§8) und `ad = H(dr_header)` (§8).
//!
//! ADR-05: Bibliothek `blake3`, keine Eigenentwicklung.

/// Länge eines Hashwerts in Bytes.
pub const HASH_LEN: usize = 32;

/// `H(x)` über einen zusammenhängenden Puffer.
#[must_use]
pub fn h(data: &[u8]) -> [u8; HASH_LEN] {
    *blake3::hash(data).as_bytes()
}

/// `H(x)` über mehrere Teile, ohne sie vorher zu kopieren.
///
/// **Achtung:** Diese Funktion hasht die reine Konkatenation. Sie ist damit
/// *nicht* das `‖` aus `spec/protokoll-spec.md` §1, das ein Längenpräfix
/// verlangt. Für Signatur-Eingaben ist die längenpräfigierte Kodierung aus
/// `vault-wire::lenprefix` zu verwenden und deren Ergebnis hier zu hashen.
#[must_use]
pub fn h_parts(parts: &[&[u8]]) -> [u8; HASH_LEN] {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, reason = "Testcode")]
mod tests {
    use super::*;

    /// Die offiziellen BLAKE3-Testvektoren (`test_vectors.json` des
    /// BLAKE3-Projekts) sind im lokal vorliegenden Crate-Paket nicht
    /// enthalten und durften nicht aus dem Netz geholt werden.
    #[test]
    #[ignore = "offizielle BLAKE3-Testvektoren fehlen lokal — siehe TAGESBERICHT.md"]
    fn blake3_offizielle_vektoren() {
        panic!("Testvektoren bereitstellen, dann implementieren");
    }

    #[test]
    fn laenge_und_determinismus() {
        let a = h(b"vault");
        let b = h(b"vault");
        assert_eq!(a.len(), HASH_LEN);
        assert_eq!(a, b);
        assert_ne!(a, h(b"vaulu"), "ein Bit Unterschied muss durchschlagen");
    }

    #[test]
    fn h_parts_entspricht_der_konkatenation() {
        assert_eq!(h_parts(&[b"ab", b"cd"]), h(b"abcd"));
    }

    #[test]
    fn h_parts_ist_ohne_laengenpraefix_mehrdeutig() {
        // Genau der Grund, warum die Doku auf vault-wire::lenprefix verweist:
        // ohne Längenpräfix kollidieren verschiedene Feldaufteilungen.
        assert_eq!(h_parts(&[b"a", b"bc"]), h_parts(&[b"ab", b"c"]));
    }
}
