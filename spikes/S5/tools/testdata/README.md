# SYNTHETISCHE Testdaten — keine Messwerte

**Nichts in diesem Verzeichnis ist gemessen.** Alle Dateien sind erzeugte oder
von Hand nachgebaute Beispiele, mit denen die Auswertelogik geprüft wird. Es
lag kein Android-Gerät vor (siehe `../../BERICHT.md` §1).

| Datei | Was es ist |
|---|---|
| `gen-synthetic.sh` | Generator für `synthetic-runs/`. Die Entladeraten darin sind **frei gewählte Rechenkonstanten** (R0 ≈ 4, R3 ≈ 11, R4 ≈ 15 %/24 h), gewählt damit ein Kriterium besteht, eines reißt und ein Lauf verworfen wird. **Keine Erwartungswerte für Vault.** |
| `synthetic-runs/` | 19 erzeugte Läufe in 6 Reihen, davon einer absichtlich ungültig (Display an) |
| `synthetic-batterystats-history.txt` | Formatprobe für `dumpsys batterystats --history` |
| `synthetic-batterystats-checkin.txt` | Formatprobe für `dumpsys batterystats --checkin` |
| `synthetic-thermalservice.txt` | Formatprobe `dumpsys thermalservice`, ohne Throttling |
| `synthetic-thermalservice-throttled.txt` | Gegenprobe mit Throttling (Status 1 und 2) |
| `fake-adb/adb` | synthetischer adb-Ersatz für den Trockenlauf `../smoke-test.sh` |

Alle Sample-CSV tragen `# synthetic=true` im Kopf. `s5-eval verdict` erkennt
das, schreibt eine Warnung und bricht mit Exitcode 3 ab, solange nicht
`--allow-synthetic` gesetzt ist. Damit kann eine Werkzeugprobe nicht
versehentlich als Messergebnis in einen Bericht oder ADR wandern.

Neu erzeugen:

```sh
sh spikes/S5/tools/testdata/gen-synthetic.sh
```
