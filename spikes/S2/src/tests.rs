//! Kontrolltests der Krypto-/Ratchet-Schicht.
//!
//! Zweck: nachweisen, dass die gemessenen Fehler der Simulation vom
//! **Zustellmodell** kommen und nicht von einer kaputten Ratchet-Verdrahtung.

use crate::crypto::{self, DerivedKeyRng, Ratchet};
use crate::vendor_dr::{DecryptError, KeyPair as _};

const AD: &[u8] = b"vault-s2";

fn pair(tag: &[u8]) -> (Ratchet, Ratchet, DerivedKeyRng, DerivedKeyRng) {
    let seed = crypto::h(&[tag, b"seed"]);
    let kp = crypto::KeyPair::from_bytes(crypto::h(&[&seed, b"spk"]));
    let pk = kp.public().clone();
    let sk = crypto::sym_from(crypto::h(&[&seed, b"sk"]));
    let mut arng = DerivedKeyRng::new(crypto::h(&[&seed, b"a"]));
    arng.prime(None);
    let a = Ratchet::new_alice(&sk, pk, None, &mut arng);
    let sk2 = crypto::sym_from(crypto::h(&[&seed, b"sk"]));
    let b = Ratchet::new_bob(sk2, kp, None);
    let brng = DerivedKeyRng::new(crypto::h(&[&seed, b"b"]));
    (a, b, arng, brng)
}

#[test]
fn round_trip_beide_richtungen() {
    let (mut a, mut b, mut ar, mut br) = pair(b"rt");
    ar.prime(a.dhr_public());
    let (h1, c1) = match a.try_ratchet_encrypt(b"hallo", AD, &mut ar) {
        Ok(v) => v,
        Err(e) => panic!("encrypt: {:?}", e),
    };
    assert_eq!(b.ratchet_decrypt(&h1, &c1, AD), Ok(b"hallo".to_vec()));
    br.prime(b.dhr_public());
    let (h2, c2) = match b.try_ratchet_encrypt(b"zurueck", AD, &mut br) {
        Ok(v) => v,
        Err(e) => panic!("encrypt: {:?}", e),
    };
    assert_eq!(a.ratchet_decrypt(&h2, &c2, AD), Ok(b"zurueck".to_vec()));
}

#[test]
fn out_of_order_erzeugt_skipped_keys() {
    let (mut a, mut b, mut ar, _br) = pair(b"ooo");
    let mut msgs = Vec::new();
    for i in 0..500u32 {
        ar.prime(a.dhr_public());
        let pt = i.to_le_bytes();
        match a.try_ratchet_encrypt(&pt, AD, &mut ar) {
            Ok(v) => msgs.push(v),
            Err(e) => panic!("encrypt: {:?}", e),
        }
    }
    // Nur die letzte Nachricht zustellen -> 499 Skipped Keys.
    let last = match msgs.last() {
        Some(v) => v.clone(),
        None => panic!("leer"),
    };
    assert!(b.ratchet_decrypt(&last.0, &last.1, AD).is_ok());
    assert_eq!(b.skipped_key_count(), 499);
    // Danach kommen die uebrigen an und werden korrekt entschluesselt.
    for (i, (h, c)) in msgs.iter().enumerate().take(499) {
        let pt = b.ratchet_decrypt(h, c, AD);
        assert_eq!(pt, Ok((i as u32).to_le_bytes().to_vec()));
    }
    assert_eq!(b.skipped_key_count(), 0);
}

#[test]
fn max_skip_grenze_greift() {
    let (mut a, mut b, mut ar, _br) = pair(b"skip");
    let mut last = None;
    for i in 0..1002u32 {
        ar.prime(a.dhr_public());
        let pt = i.to_le_bytes();
        match a.try_ratchet_encrypt(&pt, AD, &mut ar) {
            Ok(v) => last = Some(v),
            Err(e) => panic!("encrypt: {:?}", e),
        }
    }
    let (h, c) = match last {
        Some(v) => v,
        None => panic!("leer"),
    };
    // Sprung um 1001 > MAX_SKIP (1000)
    assert_eq!(
        b.ratchet_decrypt(&h, &c, AD),
        Err(DecryptError::SkipTooLarge)
    );
}

#[test]
fn replay_wird_abgewiesen() {
    let (mut a, mut b, mut ar, _br) = pair(b"replay");
    ar.prime(a.dhr_public());
    let (h, c) = match a.try_ratchet_encrypt(b"x", AD, &mut ar) {
        Ok(v) => v,
        Err(e) => panic!("encrypt: {:?}", e),
    };
    assert!(b.ratchet_decrypt(&h, &c, AD).is_ok());
    assert!(b.ratchet_decrypt(&h, &c, AD).is_err());
}

#[test]
fn geteilter_zustand_ist_deterministisch_reproduzierbar() {
    // Kontrolle fuer das Modell von Variante A: zwei Replikate desselben
    // Zustands erzeugen bei gleicher Operationsfolge byte-identische
    // Envelopes. Divergenz in der Simulation ist also echte Divergenz.
    let (mut a, mut b, mut ar, mut br) = pair(b"clone");
    ar.prime(a.dhr_public());
    let (h1, c1) = match a.try_ratchet_encrypt(b"m1", AD, &mut ar) {
        Ok(v) => v,
        Err(e) => panic!("encrypt: {:?}", e),
    };
    assert!(b.ratchet_decrypt(&h1, &c1, AD).is_ok());
    let mut b2 = b.clone();
    let mut br2 = DerivedKeyRng::new(crypto::h(&[b"clone", b"seed"]));
    // gleicher Geraete-Seed wie br
    br2 = {
        let seed = crypto::h(&[b"clone", b"seed"]);
        DerivedKeyRng::new(crypto::h(&[&seed, b"b"]))
    };
    br.prime(b.dhr_public());
    br2.prime(b2.dhr_public());
    let e1 = match b.try_ratchet_encrypt(b"ack", AD, &mut br) {
        Ok(v) => v,
        Err(e) => panic!("encrypt: {:?}", e),
    };
    let e2 = match b2.try_ratchet_encrypt(b"ack", AD, &mut br2) {
        Ok(v) => v,
        Err(e) => panic!("encrypt: {:?}", e),
    };
    assert_eq!(e1.0.n, e2.0.n);
    assert_eq!(e1.1, e2.1);
}

#[test]
fn divergenz_wird_erkannt() {
    // Zwei Replikate, unterschiedliche Operationsfolge -> unterschiedliche
    // Envelopes fuer denselben Klartext.
    let (mut a, mut b, mut ar, mut br) = pair(b"div");
    ar.prime(a.dhr_public());
    let (h1, c1) = match a.try_ratchet_encrypt(b"m1", AD, &mut ar) {
        Ok(v) => v,
        Err(e) => panic!("encrypt: {:?}", e),
    };
    assert!(b.ratchet_decrypt(&h1, &c1, AD).is_ok());
    let mut b2 = b.clone();
    let seed = crypto::h(&[b"div", b"seed"]);
    let mut br2 = DerivedKeyRng::new(crypto::h(&[&seed, b"b"]));
    // b sendet zuerst ein anderes Ack -> Kette laeuft auseinander
    br.prime(b.dhr_public());
    let _ = b.try_ratchet_encrypt(b"ack-frueher", AD, &mut br);
    br.prime(b.dhr_public());
    let e1 = match b.try_ratchet_encrypt(b"ack", AD, &mut br) {
        Ok(v) => v,
        Err(e) => panic!("encrypt: {:?}", e),
    };
    br2.prime(b2.dhr_public());
    let e2 = match b2.try_ratchet_encrypt(b"ack", AD, &mut br2) {
        Ok(v) => v,
        Err(e) => panic!("encrypt: {:?}", e),
    };
    assert_ne!(e1.0.n, e2.0.n);
}

#[test]
fn parallele_sender_verlieren_das_zweite_ack() {
    // Kern des Befunds F-1 unter der **guenstigsten** Modellannahme
    // (kanonisch abgeleitete Ratchet-Schluessel, siehe crypto.rs):
    // beide Replikate erzeugen denselben DH-Ratchet-Schluessel, der
    // Wurzelschluessel bleibt konsistent — aber die Kettenposition
    // kollidiert und das zweite Ack ist unrettbar verloren.
    let (mut a, mut b, mut ar, mut br) = pair(b"root");
    ar.prime(a.dhr_public());
    let (h1, c1) = match a.try_ratchet_encrypt(b"m1", AD, &mut ar) {
        Ok(v) => v,
        Err(e) => panic!("encrypt: {:?}", e),
    };
    assert!(b.ratchet_decrypt(&h1, &c1, AD).is_ok());
    let mut b2 = b.clone();
    let seed = crypto::h(&[b"root", b"seed"]);
    let mut br2 = DerivedKeyRng::new(crypto::h(&[&seed, b"b"]));

    // Geraet 1 (b) quittiert -> DH-Ratchet, Kontakt zieht nach.
    br.prime(b.dhr_public());
    let (ha, ca) = match b.try_ratchet_encrypt(b"ack1", AD, &mut br) {
        Ok(v) => v,
        Err(e) => panic!("encrypt: {:?}", e),
    };
    assert!(a.ratchet_decrypt(&ha, &ca, AD).is_ok());

    // Geraet 2 (b2) hat davon nichts mitbekommen und quittiert ebenfalls.
    br2.prime(b2.dhr_public());
    let (hb, cb) = match b2.try_ratchet_encrypt(b"ack2", AD, &mut br2) {
        Ok(v) => v,
        Err(e) => panic!("encrypt: {:?}", e),
    };
    // Der Kontakt hat den Schluessel dieser Kettenposition bereits verbraucht.
    assert!(a.ratchet_decrypt(&hb, &cb, AD).is_err());

    // Unter kanonischer Schluesselableitung koennen beide Replikate die
    // naechste Nachricht des Kontakts noch lesen.
    ar.prime(a.dhr_public());
    let (h2, c2) = match a.try_ratchet_encrypt(b"m2", AD, &mut ar) {
        Ok(v) => v,
        Err(e) => panic!("encrypt: {:?}", e),
    };
    assert!(b.ratchet_decrypt(&h2, &c2, AD).is_ok());
    assert!(b2.ratchet_decrypt(&h2, &c2, AD).is_ok());
}

#[test]
fn echte_zufallsschluessel_zerstoeren_die_session_dauerhaft() {
    // Gegenprobe ohne die guenstige Modellannahme: wenn das zweite Geraet
    // seinen DH-Ratchet-Schluessel aus echter Entropie zieht (also bevor ein
    // `dr_delta` mit dem privaten Ratchet-Schluessel eingetroffen ist),
    // divergiert der Wurzelschluessel und die Session ist fuer dieses Geraet
    // dauerhaft unbrauchbar.
    let (mut a, mut b, mut ar, mut br) = pair(b"root2");
    ar.prime(a.dhr_public());
    let (h1, c1) = match a.try_ratchet_encrypt(b"m1", AD, &mut ar) {
        Ok(v) => v,
        Err(e) => panic!("encrypt: {:?}", e),
    };
    assert!(b.ratchet_decrypt(&h1, &c1, AD).is_ok());
    let mut b2 = b.clone();
    // Abweichender Seed = abweichender Ratchet-Schluessel.
    let mut br2 = DerivedKeyRng::new(crypto::h(&[b"root2", b"anderer-zufall"]));

    br.prime(b.dhr_public());
    let (ha, ca) = match b.try_ratchet_encrypt(b"ack1", AD, &mut br) {
        Ok(v) => v,
        Err(e) => panic!("encrypt: {:?}", e),
    };
    assert!(a.ratchet_decrypt(&ha, &ca, AD).is_ok());

    br2.prime(b2.dhr_public());
    let (hb, cb) = match b2.try_ratchet_encrypt(b"ack2", AD, &mut br2) {
        Ok(v) => v,
        Err(e) => panic!("encrypt: {:?}", e),
    };
    // Der Kontakt kann dieses Ack gar nicht erst lesen: sein Wurzelschluessel
    // ist bereits durch das Ack von Geraet 1 fortgeschritten, waehrend
    // Geraet 2 vom alten Wurzelschluessel abgeleitet hat.
    assert!(a.ratchet_decrypt(&hb, &cb, AD).is_err());

    // Schlimmer: Geraet 2 hat seinen eigenen Wurzelschluessel auf einen Wert
    // fortgeschrieben, den der Kontakt nie annehmen wird. Es kann kuenftige
    // Nachrichten des Kontakts nicht mehr entschluesseln — dauerhaft.
    ar.prime(a.dhr_public());
    let (h2, c2) = match a.try_ratchet_encrypt(b"m2", AD, &mut ar) {
        Ok(v) => v,
        Err(e) => panic!("encrypt: {:?}", e),
    };
    assert!(b.ratchet_decrypt(&h2, &c2, AD).is_ok());
    assert!(b2.ratchet_decrypt(&h2, &c2, AD).is_err());
}
