# Spike S2 — Multi-Device-Ratchet-Sync

**Spike-Code. Gehoert nicht nach `core/` oder `app/` und wird nicht ausgeliefert.**
Zweck ist eine Entscheidung fuer GATE-2, kein Produkt.

Spec: `spec/phase0-spikeplan.md` §2 (S2), §4 (GATE-2), §6 (R-3);
`spec/protokoll-spec.md` §2, §8, §9, §10; `spec/gesamtkonzept.md` §2.6.

## Inhalt

| Pfad | Inhalt |
|---|---|
| `src/vendor_dr.rs` | **Vendortes Fremdmaterial**: Double Ratchet aus crate `double-ratchet` 0.1.0 (BSD-3-Clause). Aenderungen im Dateikopf vollstaendig aufgelistet. |
| `LICENSE-double-ratchet` | Lizenz des vendorten Codes |
| `src/crypto.rs` | `CryptoProvider`: X25519, HKDF-SHA-256, HMAC-SHA-256, XChaCha20-Poly1305, BLAKE3 — echte Bibliotheken nach `protokoll-spec.md` §1 |
| `src/sim.rs` | Ereignisgesteuerte Simulation des Zustellmodells (§9, §10) |
| `src/tests.rs` | Kontrolltests der Ratchet-Schicht |
| `src/main.rs` | Runner (rayon, deterministische Seeds) |
| `analyze/` | Auswertung der Rohdaten |
| `data/` | Rohdaten (JSON Lines, eine Zeile je Lauf) |
| `BERICHT.md` | Messergebnisse und Empfehlung |
| `adr-entwurf-GATE-2.md` | ADR-Entwurf |

## Reproduktion

```
cd spikes/S2
cargo test  --release                       # 8 Kontrolltests der Ratchet-Schicht
cargo run   --release -- 10000 1 data/main10k.jsonl     # Hauptkampagne
cargo run   --release -- 2000  3 data/lat3.jsonl        # Latenz-Sensitivitaet
cd analyze && cargo run --release -- ../data/main10k.jsonl
```

Argumente: `<Laeufe je Variante> <Latenzmultiplikator> <Ausgabedatei>`.
Seeds sind fest (`0x5EED…` + Laufindex), Laeufe sind reproduzierbar und
ueber alle Varianten szenario-identisch.

## Varianten

| ID | Modell |
|---|---|
| **A** | Eine gemeinsame Kontakt-Session, `dr_delta` ueber das paarweise Geschwister-Mesh (`protokoll-spec.md` §9.3 im Wortlaut) |
| **A-reconcile** | wie A, zusaetzlich Zustandssnapshot vom kanonischen Geraet 0 bei erkannter Divergenz |
| **B** | Primaergeraet haelt den kanonischen Zustand; Zweitgeraete sind Read-Through-Replikate mit Store-and-Forward/Send-Proxy (Fallback aus `protokoll-spec.md` §9.3) |
| **A2** | *informativ, nicht beauftragt*: je eigenem Geraet eine eigene Kontakt-Session, Geschwister-Sync nur mit Klartext |

## Zeitmodell

Alle Zeiten sind **simuliert** (Einheit ms). Es wird nie real gewartet.
Abbildung simulierter auf reale Zeit: 1:1. Die Simulation setzt
Tor-Onion-Einwegverzoegerungen von 1,5–7,5 s (gleichverteilt) an; der
Latenzmultiplikator skaliert diese Annahme. Weitere Parameter in
`src/sim.rs` (Konstanten am Dateikopf).
