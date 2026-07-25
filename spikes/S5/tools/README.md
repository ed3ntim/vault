# S5 — Werkzeuge

Alles hier ist Spike-Werkzeug nach `CLAUDE.md` („Aller Code liegt unter
`spikes/<id>/`"). Nichts davon ist Produktionscode, nichts hängt an `core/`.

```
tools/
├─ collect/        Erfassung am Geraet (POSIX sh + adb)
│  ├─ _common.sh        dumpsys-Auswertung, gemeinsame Helfer
│  ├─ s5-precheck.sh    Geraetezustand vor dem Lauf pruefen
│  ├─ s5-start-run.sh   Statistik zuruecksetzen, Metadaten festhalten
│  ├─ s5-end-run.sh     Rohdaten holen, Fuellstandskurve rekonstruieren
│  └─ s5-sample.sh      OPTIONALER Mitschnitt (Messartefakt, siehe Kopf)
├─ s5-eval/        Auswertung (Rust, nur std, keine Dependencies)
├─ testdata/       synthetische Beispieldaten + adb-Ersatz
└─ smoke-test.sh   Trockenlauf des gesamten Kits ohne Geraet
```

## Bauen und prüfen

```sh
cargo build --release --manifest-path spikes/S5/tools/s5-eval/Cargo.toml
cargo test            --manifest-path spikes/S5/tools/s5-eval/Cargo.toml
sh spikes/S5/tools/smoke-test.sh
```

Erwartung: 28 Tests grün (23 Unit, 5 Integration), Trockenlauf 22 Schritte grün.

## `s5-eval`

| Kommando | Zweck |
|---|---|
| `s5-eval run <samples.csv>` | Kennzahlen eines Laufs: Entladerate %/24 h (lineare Regression über alle Füllstandswechsel), Coulomb-Rate, Temperatur, Thermal-Status, Gültigkeit |
| `s5-eval verdict <verzeichnis>` | alle Läufe einlesen, nach Gerät und Reihe gruppieren, Kriterien K-A1/K-A2/K-B/K-C entscheiden |
| `s5-eval history <dump>` | `dumpsys batterystats --history` → Sample-CSV |
| `s5-eval thermal <dump>` | `dumpsys thermalservice` → Throttling-Prüfung |
| `s5-eval batterystats <checkin>` | `dumpsys batterystats --checkin` → Verbrauchszuordnung (informativ) |

Exitcodes von `verdict`: `0` alle Kriterien bestanden · `1` mindestens eines
gerissen · `2` unentschieden oder zu wenig Daten · `3` Eingabefehler oder
synthetische Daten ohne `--allow-synthetic`.

### Entscheidungsregel
Nicht der Mittelwert entscheidet, sondern das **einseitige 95-%-Konfidenz-
intervall der Differenz** zweier Reihen (Welch). Liegt es ganz unter der
Schwelle: bestanden. Ganz darüber: gerissen. Enthält es die Schwelle:
unentschieden — dann nennt das Werkzeug die empfohlene Laufzahl.
Begründung in `../MESSPROTOKOLL.md` §8.

### Sample-CSV-Format
```
# s5-sample v1
# series=R3
# device=DEV-A
# design_capacity_uah=4000000
t_unix,level_pct,charge_uah,voltage_uv,temp_dc,thermal_status,screen_on,plugged
1750000000,95,3800000,4180000,300,0,0,0
```
Pflichtspalten `t_unix` und `level_pct`; alles andere optional und für
Gültigkeitsprüfungen genutzt. Fehlende Werte als `-`.

## Womit die Werkzeuge getestet sind

**Ausschließlich mit synthetischen Daten** — es gab kein Gerät.

| Prüfling | Testdaten |
|---|---|
| Regression, Welch, t-Quantile, benötigte Laufzahl | Unit-Tests mit analytisch nachrechenbaren Reihen |
| Sample-CSV-Parser und Gültigkeitsregeln | im Test erzeugte Läufe (auch fehlerhafte: Laden, Display an, zu kurz) |
| Reihenaggregation und Urteil | `testdata/synthetic-runs/` (19 Läufe, erzeugt von `testdata/gen-synthetic.sh`) |
| `--history`-Parser | `testdata/synthetic-batterystats-history.txt` |
| `--checkin`-Parser | `testdata/synthetic-batterystats-checkin.txt` |
| `thermalservice`-Parser | `testdata/synthetic-thermalservice.txt` und `-throttled.txt` |
| Erfassungsskripte | `testdata/fake-adb/adb` über `smoke-test.sh` |

**Vorbehalt:** Die drei `dumpsys`-Parser sind nach der dokumentierten
AOSP-Ausgabe gebaut, nicht gegen ein echtes Gerät verifiziert. Alle drei geben
ihre Trefferzahl aus und brechen bei unplausibler Ausbeute ab, statt still
falsche Zahlen zu liefern. Beim ersten echten Dump ist das Format zu prüfen
(`../VORAUSSETZUNGEN.md` §4, Werkzeug-Vorbehalt).

## Regeln, die auch für Spike-Code gelten

- `#![forbid(unsafe_code)]`, keine externen Crates, kein `unwrap()` in
  Bibliothekscode.
- Kein Netzverkehr außer `adb` zum lokal angeschlossenen Messgerät. Kein
  Upload, keine Telemetrie (ADR-14).
- Keine Schlüssel, Onion-Adressen, Kontakt-IDs oder Klartexte in den
  Ausgaben. Die Skripte lesen ausschließlich Systemzähler. Gerätebezeichner ist
  ein frei gewähltes Label, nicht die Seriennummer.
- Bugreports bleiben lokal und kommen nicht ins Repository.
