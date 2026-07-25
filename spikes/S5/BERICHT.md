# S5 — Bericht: Akkuverbrauch unter Dauer-Onion

**Stand:** Vorbereitung abgeschlossen, Messung nicht durchgeführt.
**Ergebnis in einem Satz:** S5 ist **offen** — weder bestanden noch gescheitert.

Es standen in dieser Umgebung **keine Referenzgeräte und kein Android-Gerät**
zur Verfügung. Es wurde deshalb kein einziger Messwert erhoben, und es sind
keine geschätzten Werte eingesetzt worden. Geliefert ist ein benutzbares
Mess-Kit, kein Messergebnis.

---

## 1. Messergebnisse gegen die Erfolgskriterien

`spec/phase0-spikeplan.md` §2, S5:

| # | Kriterium | Gemessen | Grund |
|---|---|---|---|
| K-A | Zusatzverbrauch < 8 %/24 h im Leerlauf | **keine Daten** | kein Gerät; keine messbare App (`VORAUSSETZUNGEN.md` §4) |
| K-B | BLE-Beacons < 2 %/24 h zusätzlich | **keine Daten** | dito; zusätzlich keine Beacon-Implementierung |
| K-C | Kein Thermal-Throttling | **keine Daten** | dito |

Null Läufe, null Geräte, null Werte. Jede Zahl an dieser Stelle wäre erfunden.

Was stattdessen **gemessen** wurde, ist das Werkzeug selbst:

| Prüfung | Ergebnis |
|---|---|
| Unit- und Integrationstests `s5-eval` | **28 Tests, 28 bestanden, 0 fehlgeschlagen** (23 Unit, 5 Integration) |
| Trockenlauf des gesamten Kits ohne Gerät (`tools/smoke-test.sh`) | **22 Prüfschritte, alle bestanden** |
| Syntaxprüfung aller Shell-Skripte (`sh -n`) | 6/6 fehlerfrei |
| Externe Abhängigkeiten von `s5-eval` | 0 (nur `std`), `#![forbid(unsafe_code)]` |
| Netzzugriffe der Werkzeuge | 0 (nur adb zum lokal angeschlossenen Gerät) |

---

## 2. Was vorbereitet ist

| Datei | Inhalt |
|---|---|
| `MESSPROTOKOLL.md` | Durchführungsanweisung: 6 Messreihen + 3 Kontrollreihen, Randbedingungen, Rücksetz-Checkliste, Reihenfolge/Gegenbalancierung, Wiederholungszahl mit Begründung, Kalenderrechnung gegen die Timebox, Ablauf Schritt für Schritt |
| `VORAUSSETZUNGEN.md` | Geräte, Android-Version, Werkzeuge, Geräteeinstellungen, App-Bestandteile — mit Kennzeichnung, was **nicht existiert** |
| `tools/s5-eval/` | Auswertewerkzeug (Rust, `std`-only): Entladerate je Lauf, Gültigkeitsprüfung, Reihenaggregation, Welch-Konfidenzintervalle, Urteil je Kriterium, Thermal-Prüfung, Verbrauchszuordnung |
| `tools/collect/` | `s5-precheck.sh`, `s5-start-run.sh`, `s5-end-run.sh`, `s5-sample.sh` (optional), `_common.sh` |
| `tools/smoke-test.sh` | Trockenlauf des Kits ohne Gerät gegen einen synthetischen adb-Ersatz |
| `tools/testdata/` | synthetische Beispieldaten samt Generator, ausdrücklich als **keine Messwerte** gekennzeichnet |
| `adr-entwurf-GATE-3.md` | ADR-Entwurf mit den Profilparametern als offene Felder |

Die Kriterien der Spec sind im Werkzeug direkt kodiert: `s5-eval verdict`
rechnet sie aus den Rohdaten aus und liefert je Kriterium
bestanden / gerissen / unentschieden samt Konfidenzintervall.

**Womit die Skripte getestet wurden:** ausschließlich mit synthetischen Daten.

- `tools/testdata/synthetic-runs/` — 19 erzeugte Läufe (6 Reihen × 3 + ein
  absichtlich ungültiger Lauf), erzeugt von `tools/testdata/gen-synthetic.sh`.
  Die Entladeraten darin sind **frei gewählte Rechenkonstanten**, keine
  Erwartungswerte für Vault. Sie sind so gewählt, dass ein Kriterium besteht,
  eines reißt und ein Lauf verworfen wird — damit alle Zweige der Logik laufen.
- `tools/testdata/synthetic-batterystats-history.txt`,
  `synthetic-batterystats-checkin.txt`, `synthetic-thermalservice*.txt` —
  Formatproben, nachgebaut nach der dokumentierten AOSP-Ausgabe.
- `tools/testdata/fake-adb/adb` — synthetischer adb-Ersatz für den Trockenlauf.

Jede synthetische Datei ist als solche markiert. `s5-eval verdict` bricht bei
synthetischen Eingaben mit Exitcode 3 ab, sofern nicht ausdrücklich
`--allow-synthetic` gesetzt ist, und schreibt eine Warnung in die Ausgabe.
Damit kann eine Werkzeugprobe nicht versehentlich als Messergebnis zitiert
werden.

---

## 3. Was gemessen werden kann — und was nicht

### 3.1 Sofort messbar, sobald Geräte da sind (ohne App)
- **R0** (Baseline idle), **R5** (Referenz-Messenger), **K1** (Flugmodus ohne
  App), **K3** (Eigenverbrauch des Mitschnitts).
- Nutzen: Diese Läufe liefern die **Streuung der Baseline**. Genau daran hängt,
  wie viele Wiederholungen die Kriterien überhaupt entscheidbar machen
  (`MESSPROTOKOLL.md` §8.2). Außerdem verifizieren sie die Parser gegen echte
  Dumps statt gegen Formatproben.

### 3.2 Nicht messbar, solange die App fehlt
R1–R4 und K2. Es gibt keinen Foreground-Service, keinen Onion-Betrieb, kein
Shaping und keine Beacons (`VORAUSSETZUNGEN.md` §4: A-1 bis A-9 sämtlich ❌).
`core/` besteht aus ~1.240 Zeilen Gerüst; ein `app/`-Verzeichnis existiert nicht.

### 3.3 Grundsätzlich nicht durch S5 entscheidbar
- **iOS.** GATE-5 zieht S5 als Input heran, aber iOS hat keinen persistenten
  Hintergrundprozess (`gesamtkonzept.md` §2.12). Für iOS gibt es keinen
  Dauer-Onion-Betrieb, dessen Verbrauch man messen könnte. GATE-5 entscheidet
  sich an §2.12/§6 und an E1/E2, nicht an S5.
- **Feldverhalten.** Gemessen wird ein definierter Laborzustand (fester
  Aufstellort, 1 Beacon-Gegenstelle, 5 Kontakte, WLAN). Reale Nutzung —
  wechselnde Netze, viele Kontakte, volle Innenstadt voller BLE-Geräte —
  liegt darüber. Das Ergebnis ist eine untere Schranke, keine Alltagsprognose.
- **Langzeitverhalten.** 24-h-Läufe sagen nichts über Akkualterung durch
  Dauerlast über Monate.

---

## 4. Was ich nicht prüfen konnte

| Punkt | Warum |
|---|---|
| Alle drei Erfolgskriterien | kein Android-Gerät, keine messbare App |
| Ob `dumpsys batterystats --history` kumulative oder inkrementelle Zeitangaben liefert | kein Gerät; Parser unterstützt beides, `--deltas` schaltet um, nicht-monotone Offsets werden erkannt und gemeldet |
| Ob `batterystats --checkin` auf aktuellen Android-Versionen noch `pwi`-Zeilen liefert | kein Gerät; das Format ist versionsabhängig, ab Android 12 wird `--proto` bevorzugt. Das Werkzeug meldet die Trefferzahl und sagt ausdrücklich, dass 0 Treffer ein Formatproblem und kein Ergebnis sind |
| Ob `dumpsys deviceidle get screen` auf allen Geräten existiert | kein Gerät; `_common.sh` fällt auf `dumpsys power`/`mWakefulness` zurück |
| Ob der Coulomb-Zähler (`Charge counter`) verfügbar ist | geräteabhängig; die Auswertung funktioniert auch ohne, dann nur über Füllstandsregression |
| Reale Streuung der Baseline und damit die tatsächlich nötige Laufzahl | erst mit Geräten bestimmbar — deshalb die sequenzielle Regel statt einer geratenen Fallzahl |
| Ob Hersteller-Energiemanagement (Samsung/Xiaomi) den Foreground-Service killt | kein Gerät; das ist ein eigenes Risiko für das Zustellmodell, nicht nur für den Akku, und gehört in dieselbe Kampagne |
| Verhalten unter Mobilfunk statt WLAN | nicht im Spec-Umfang; als optionale Variante V-LTE beschrieben, Entscheidung offen |

---

## 5. Bewertung der Fallback-Kaskade

Die Spec gibt vor (`phase0-spikeplan.md` §2, S5):

> **Fallback-Kaskade:** Shaping-Budget reduzieren → Beacon-Intervall auf
> 60–120 s → adaptives Verhalten bei Akkustand < 20 % (**Achtung:** darf kein
> unterscheidbares Netzprofil erzeugen — Anpassung nur bei Mesh, nicht beim
> Tor-Profil).

Die folgende Bewertung ist **Analyse anhand der Spec**, keine Messung.

### Vorbedingung für die ganze Kaskade
Keine Stufe darf betreten werden, bevor die Zwischenschritte zeigen, dass der
jeweilige Hebel überhaupt greift. Genau dafür misst das Kit R1−R0, R2−R1,
R3−R2 und R4−R3 getrennt. Wer das Shaping-Budget senkt, obwohl R3−R2 klein ist,
opfert Schutz gegen G2/G3 (`threat-model.md`) **ohne** Akkugewinn. Das wäre der
schlechteste mögliche Tausch.

### Stufe 1 — Shaping-Budget reduzieren
- Betrifft das **Tor-Profil**. Zulässig ausschließlich als **einmalige, globale
  Neufestlegung** einer Konstante vor dem Release: für alle Nutzer identisch,
  nicht zur Laufzeit, nicht pro Gerät, nicht pro Akkustand, nicht konfigurierbar
  (`gesamtkonzept.md` §2.9; ADR-09).
- Preis: schwächt die ohnehin nur teilweise wirksamen Minderungen gegen
  **G2** (Ende-zu-Ende-Timing-Korrelation) und **G3** (Online-Zeiten aus
  Verbindungsaufkommen) — beide in `threat-model.md` mit ◐ bewertet.
- Diese Stufe ist deshalb **nicht** allein aus S5 zu entscheiden. Sie gehört mit
  S4 zusammen in GATE-3.

### Stufe 2 — Beacon-Intervall 60–120 s
- Betrifft nur **Mesh** — nach Spec-Vorgabe zulässig.
- Aber es ist keine reine Stellschraube: `protokoll-spec.md` §13 definiert
  `epoch = floor(t / 30)`; das Intervall geht in die **Token-Ableitung** ein.
  Beide Seiten müssen dasselbe Raster verwenden, sonst findet keine Erkennung
  statt. Eine Änderung ist damit eine **Protokolländerung** (Spec-Fortschreibung
  in §13), eine globale Konstante — kein Laufzeitparameter.
- Folgen: Begegnungserkennung dauert bis zu 4-mal länger; ein Token ist länger
  gültig, was das Zeitfenster für Beobachtungsversuche vergrößert (die
  Challenge-Response-Frische im anschließenden Handshake bleibt wirksam,
  `protokoll-spec.md` §13).
- Kein neues Unterscheidbarkeitsproblem, solange das Intervall **für alle
  Nutzer gleich** ist. Dass eine App überhaupt in einem festen Raster sendet,
  ist ein lokal sichtbares Merkmal — das gilt für 30 s wie für 120 s (G7,
  Bestandsrisiko).

### Stufe 3 — adaptives Verhalten bei Akkustand < 20 %
Hier liegt das eigentliche Risiko, und es ist größer, als die Formulierung
vermuten lässt.

- **Verboten bleibt jede Anpassung am Tor-Profil.** Ein Netzbeobachter darf aus
  dem Verkehr nicht ableiten können, wie voll ein Akku ist — das wäre ein
  direkter Kanal in den Gerätezustand und würde die Nutzerbasis partitionieren
  (§2.9). Die Spec sagt das; es ist zu halten, ohne Ausnahme.
- **Auch im Mesh ist die Anpassung sichtbar.** Ein physisch anwesender
  Beobachter (Angreiferklasse **G7**, Mesh-Sniffing) sieht die Senderate
  unmittelbar. Er kann die Tokens nicht auflösen, aber er sieht, **dass** ein
  Gerät in der Nähe von 30 s auf 120 s wechselt. Daraus folgt:
  1. ein neues Metadatenleck über einen Gerätezustand (Akku niedrig), und
  2. eine Aufteilung der Beacon-Population in zwei Klassen.
- Diese Partition ist **weniger schädlich** als eine Sicherheitsstufe: Sie
  trennt nicht „die Vorsichtigen" von „den Sorglosen", sondern „gerade leer" von
  „gerade voll" — ein Zustand, der über die Nutzerbasis zufällig verteilt ist.
  Sie ist aber **nicht folgenlos**: Ein wiederkehrendes Muster (dasselbe Gerät
  wechselt jeden Abend am selben Ort in den Sparmodus) ist ein
  Wiedererkennungsmerkmal, das die rotierenden Identifier aus §2.8 gerade nicht
  abdecken — verhaltensbasiert statt kennungsbasiert.
- **Wenn Stufe 3 überhaupt kommt**, dann nur:
  - als **deterministische, in der Spec fixierte Regel**, in allen Clients
    identisch implementiert (kein Nutzerschalter, keine Herstellervariante),
  - mit **grober Hysterese** — ein einziger Schwellenübergang, keine
    kontinuierliche Anpassung, damit kein feinkörniges Verhaltensprofil entsteht,
  - **nur Mesh**, nie Tor,
  - mit einem **neuen Restrisiko im Threat Model** unter G7, ausdrücklich
    dokumentiert statt stillschweigend in Kauf genommen.

### Nicht in der Spec genannte Option (Vorlage zur Entscheidung, keine Empfehlung)
Reißt K-B (BLE < 2 %/24 h) deutlich, gäbe es einen vierten Weg: Mesh ist
Phase 4 und pro Kontakt schaltbar (`gesamtkonzept.md` §2.8, Backlog ME-6). Man
könnte Mesh-Beacons in 1.0 nicht dauerhaft laufen lassen.

Das ist **nicht** ohne Weiteres zulässig: Sobald Mesh-Dauerbetrieb eine
Nutzerentscheidung wird, partitioniert sie wieder — und §2.9 verbietet genau
das für sicherheitsrelevantes Verhalten. Ob eine Funktionsentscheidung
(„Umgebungserkennung an") in derselben Kategorie liegt wie eine
Sicherheitsentscheidung („Vorsichtsstufe hoch"), ist eine Grundsatzfrage. Sie
steht nicht in der Spec und wird hier **nicht** entschieden, sondern vorgelegt.

---

## 6. Warum S5 offen ist und was zur Entscheidung fehlt

S5 ist **nicht bestanden** (es gibt keinen Beleg) und **nicht gescheitert**
(es gibt keinen Gegenbeleg). Er ist **offen**.

Zur Entscheidung fehlen, in dieser Reihenfolge:

1. **S1** — der Tor-Stack. `phase0-spikeplan.md` §1 nennt den kritischen Pfad
   **S1 → S5 → S2**. Solange nicht feststeht, ob Arti oder C-tor läuft, ist der
   größte Einzelposten der Messung unbestimmt.
2. **Eine messbare App** — Foreground-Service, Onion-Dauerbetrieb, Snowflake,
   Shaping, BLE-Beacons, einzeln zuschaltbar (`VORAUSSETZUNGEN.md` §4, A-1…A-9).
3. **Referenzgeräte** — 2 Modelle, für die Timebox 4 Einheiten je Modell
   (`MESSPROTOKOLL.md` §8.4).
4. **Zwei Festlegungen durch den Menschen**, die die Spec offenlässt:
   - worauf sich „< 8 %/24 h" bezieht (`MESSPROTOKOLL.md` §2),
   - das Referenzprofil an Kontakten/Kompartimenten (`MESSPROTOKOLL.md` §4.6).
5. **Die Messkampagne selbst** — ~28 Gerätetage je Modell.

**Zur Timebox:** Die 8 T aus dem Spike-Plan sind für die *Durchführung*
kalkuliert, nicht für Beschaffung und App-Bau. Die Vorbereitung hat einen
kleinen Teil davon verbraucht. Die eigentliche Messung passt nur dann in die
Box, wenn parallel auf mindestens 4 baugleichen Einheiten je Modell gemessen
wird. Das ist eine Beschaffungsentscheidung, die **vor** dem Start fällt.

**Empfehlung:** S5 als offen führen, R-2 im Risikoregister unverändert auf
„sehr hoch" belassen und den Frühindikator „S5-Erstmessung Woche 3" auf die
heute schon möglichen Läufe R0/R5/K1 umdeuten — sobald Geräte da sind. Das
liefert die Baseline-Streuung und verifiziert die Parser gegen echte Dumps,
ohne auf die App zu warten.

---

## 7. Offene Punkte, die eine Entscheidung brauchen

| # | Frage | Wirkung |
|---|---|---|
| O-1 | Bezieht sich „< 8 %/24 h" auf R3−R0 oder auf R4−R0? | entscheidet über Bestehen bei identischen Daten |
| O-2 | Referenzprofil: wie viele Kontakte/Kompartimente werden gemessen? | Verbrauch skaliert damit; ohne Festlegung nicht reproduzierbar |
| O-3 | Wie viele Geräte werden beschafft (Option A/B/C aus `MESSPROTOKOLL.md` §8.4)? | entscheidet, ob die Timebox haltbar ist |
| O-4 | Wird zusätzlich unter Mobilfunk gemessen (Variante V-LTE)? | Funkanteil verhält sich anders; verdoppelt den Aufwand |
| O-5 | Ist Mesh-Dauerbetrieb als Nutzerentscheidung mit §2.9 vereinbar (§5, letzter Abschnitt)? | betrifft Priorität 1; nicht durch den Spike zu entscheiden |
| O-6 | Wird die Akkuausnahme für den Foreground-Service angefordert, und wird genau das gemessen? | verändert das Ergebnis erheblich |
