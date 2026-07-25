# Spike S5 — Akkuverbrauch unter Dauer-Onion

**Status: offen.** Weder bestanden noch gescheitert — es wurde nichts gemessen.
Es standen keine Referenzgeräte und kein Android-Gerät zur Verfügung. Statt
Messwerten liegt hier ein einsatzbereites **Mess-Kit**.

Spec: `spec/phase0-spikeplan.md` §2 (S5), §4 (GATE-3, GATE-5), §6 (R-2).

## Reihenfolge zum Lesen

| Datei | Inhalt |
|---|---|
| [`BERICHT.md`](BERICHT.md) | Was vorbereitet ist, was messbar ist, was nicht, Bewertung der Fallback-Kaskade, warum S5 offen ist |
| [`VORAUSSETZUNGEN.md`](VORAUSSETZUNGEN.md) | Geräte, Tools, Einstellungen, App-Bestandteile — und woran die Messung heute hängt |
| [`MESSPROTOKOLL.md`](MESSPROTOKOLL.md) | Durchführungsanweisung Schritt für Schritt |
| [`adr-entwurf-GATE-3.md`](adr-entwurf-GATE-3.md) | ADR-Entwurf mit offenen Feldern für die Profilparameter |
| [`tools/README.md`](tools/README.md) | Werkzeuge: Aufbau, Bau, Aufruf, Prüfstand |

## Schnellstart (ohne Gerät prüfbar)

```sh
cargo test  --manifest-path spikes/S5/tools/s5-eval/Cargo.toml   # 28 Tests
sh spikes/S5/tools/smoke-test.sh                                 # Trockenlauf des Kits
```

## Ergebnislage gegen die Erfolgskriterien

| Kriterium | Ergebnis |
|---|---|
| Zusatzverbrauch < 8 %/24 h | keine Daten |
| BLE-Beacons < 2 %/24 h zusätzlich | keine Daten |
| Kein Thermal-Throttling | keine Daten |

Alle Zahlen in `tools/testdata/` sind **synthetisch** und ausdrücklich keine
Messwerte. `s5-eval` verweigert dafür ein Gate-Urteil, sofern nicht
`--allow-synthetic` gesetzt ist.
