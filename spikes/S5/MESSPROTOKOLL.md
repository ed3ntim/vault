# S5 — Messprotokoll Akkuverbrauch unter Dauer-Onion

**Spike:** S5 (`spec/phase0-spikeplan.md` §2) · **Timebox:** 8 T · **Kritikalität:** 🔴
**Speist:** GATE-3 (Parameter des einheitlichen Netzprofils), GATE-5 (Zielplattformen)
**Risiko:** R-2 „Akkuverbrauch inakzeptabel", Frühindikator „S5-Erstmessung Woche 3"

Dieses Dokument ist die Durchführungsanweisung. Es enthält **keine Messwerte**.
Alle Zahlen darin sind Durchführungsgrenzen (Startfüllstand, Mindestdauer,
Entscheidungsregeln), keine Erwartungen an das Ergebnis.

---

## 1. Was entschieden werden muss

Wörtlich aus `spec/phase0-spikeplan.md` §2, S5:

> **Methode:**
> 1. Referenzgeräte (Mittelklasse Android, 3–4 Jahre alt) mit Foreground-Service über 24 h
> 2. Messreihen: nur Onion · +Snowflake · +Traffic-Shaping · +BLE-Beacons (30 s Intervall)
> 3. Vergleich gegen Baseline (Gerät idle) und gegen Referenz-Messenger
>
> **Erfolgskriterien:**
> - Zusatzverbrauch < 8 %/24 h im Leerlauf-Betrieb
> - BLE-Beacons < 2 %/24 h zusätzlich
> - Kein Thermal-Throttling

---

## 2. Offene Auslegungsfrage — vor der Messung zu klären

Die Spec sagt nicht eindeutig, worauf sich „Zusatzverbrauch < 8 %/24 h" bezieht.
Zwei Lesarten sind möglich:

| Lesart | Kriterium | Gesamtbudget mit Mesh |
|---|---|---|
| **A1** | Netzprofil ohne Mesh (R3 − R0) < 8 %/24 h, BLE zusätzlich < 2 | 10 %/24 h |
| **A2** | alles inklusive Mesh (R4 − R0) < 8 %/24 h, davon BLE < 2 | 8 %/24 h |

Die Lesart ist **entscheidungsrelevant** — dieselben Rohdaten können unter A1
bestehen und unter A2 reißen. `s5-eval verdict` weist deshalb beide Kriterien
getrennt aus (K-A1 und K-A2) und entscheidet die Frage nicht.

**Entschieden am 2026-09-02: Lesart A1** (`ops/autopilot/ENTSCHEIDUNGEN.md`,
Eintrag A4; `spec/phase0-spikeplan.md` §2 (S5)). Kriterientragend ist
(R3 − R0) < 8 %/24 h, dazu (R4 − R3) < 2 %/24 h; (R4 − R0) wird weiterhin
berichtet, trägt aber kein Kriterium. `s5-eval verdict` weist unverändert beide
aus. Der ADR zu GATE-3 übernimmt diese Festlegung in Feld PROFIL-0.

Zweite, kleinere Unklarheit, ebenfalls am 2026-09-02 entschieden (§4.6): Die
Spec legte nicht fest, mit **wie vielen Kontakten und Kompartimenten** gemessen
wird. Der Verbrauch skaliert damit
(Sync-Fenster pro Kontaktpaar nach `spec/protokoll-spec.md` §10, Beacon-Tokens
pro Kontakt nach §13). §4.6 dieses Protokolls schlägt ein festes Referenzprofil
vor; es ist eine **Annahme**, keine Spec-Vorgabe, und mit zu bestätigen.

---

## 3. Messreihen

Jede Reihe läuft **24 h**, Gerät unberührt, Display aus, keine Nutzerinteraktion.
„Leerlauf" heißt: keine Nutzernachrichten. Protokollverkehr (Descriptor-Republish,
Sync-Fenster, Keepalive, Shaping, Beacons) läuft normal — genau der ist die
Messgröße.

| ID | Reihe | Was aktiv ist | Wdh. |
|---|---|---|---|
| **R0** | Baseline | Gerät idle, Vault **nicht installiert** bzw. deinstalliert; sonst identischer Gerätezustand | 3 |
| **R1** | nur Onion | Foreground-Service, Onion-Service mit Client-Auth publiziert, direkter Tor-Zugang (kein PT), **kein** Shaping, **kein** BLE | 3 |
| **R2** | + Snowflake | wie R1, zusätzlich Snowflake/meek als Transport (`gesamtkonzept.md` §2.5) | 3 |
| **R3** | + Traffic-Shaping | wie R2, zusätzlich Padding auf Größenklassen und Alltags-Sendemuster (§2.5, TR-4) | 3 |
| **R4** | + BLE-Beacons | wie R3, zusätzlich PSI-Beacons im 30-s-Raster (`protokoll-spec.md` §13) inkl. Empfangspfad | 3 |
| **R5** | Referenz-Messenger | Vault deinstalliert/gestoppt, stattdessen ein etablierter Messenger im Normalzustand (kein Vault) | 3 |
| **K1** | Kontrolle Flugmodus, Vault gestoppt | Flugmodus an, Vault installiert aber Dienst gestoppt → Hardware-Grundlast des Geräts | 2 |
| **K2** | Kontrolle Flugmodus, Vault aktiv | Flugmodus an, Vault-Dienst aktiv → CPU-/Wakelock-Anteil **ohne** Funkanteil | 2 |
| **K3** | Kontrolle Mitschnitt | wie R0, zusätzlich `s5-sample.sh` mit 300 s Intervall → Eigenverbrauch des Mitschnitts | 2 |

R0–R5 tragen die Kriterien. K1–K3 tragen keine Kriterien, sondern erklären das
Ergebnis (Zuordnung) und sichern die Methode ab. K2 ist der wichtigste
Kontrolllauf: Er trennt „die App rechnet zu viel" von „das Funkmodul ist wach".

**R5-Hinweis:** Der Referenz-Messenger ist ein Vergleichsmaßstab für die
Verhältnismäßigkeit, kein Kriterium. Er nutzt Push über eine Betreiber-
Infrastruktur und ist damit strukturell im Vorteil; das ist beim Lesen des
Vergleichs zu sagen, nicht wegzurechnen.

---

## 4. Randbedingungen

Alle Punkte gelten für **jeden** Lauf identisch. Abweichungen machen den Lauf
ungültig (§9).

### 4.1 Ladezustandsfenster
- Start: **95 % ± 2** (zulässig 88–97 %, geprüft von `s5-precheck.sh`).
- Ende: nicht unter **25 %**. Grund: unterhalb davon ist die Entladekurve
  nichtlinear, und Android schaltet bei 20 %/15 % Sparmechanismen zu.
- Ladeprotokoll zwischen Läufen: gleiches Netzteil, gleiches Kabel, auf 100 %
  laden, abstecken, **mindestens 60 min abkühlen**, erst dann starten, wenn der
  Füllstand von selbst in das Startfenster gefallen ist.

### 4.2 Display und Interaktion
- Display den ganzen Lauf aus. Kein Entsperren, keine Benachrichtigungsprüfung.
- „Aktiv lassen beim Laden" in den Entwickleroptionen aus.
- `screen_on` wird aufgezeichnet; ein einziges `1` verwirft den Lauf.

### 4.3 Netz
- **Normativ für das Gate: WLAN**, dasselbe Netz, derselbe AP, derselbe
  Aufstellort, RSSI notiert (`wifi_rssi_dbm` in `run.meta`).
- Mobilfunk aus (SIM entnommen oder Mobile Data aus), sofern die Reihe nicht
  ausdrücklich Mobilfunk misst.
- Optionale Zusatzvariante V-LTE (nur Mobilfunk, kein WLAN): fachlich sehr
  erwünscht, weil der Funkanteil dort deutlich anders liegt. Sie ist **nicht
  Teil des Spec-Umfangs** und verdoppelt den Aufwand — Entscheidung durch den
  Menschen, nicht durch dieses Protokoll.

### 4.4 Doze und Systemeinstellungen
- Doze läuft **natürlich** — kein `dumpsys deviceidle force-idle`, kein
  Unstick. Gemessen wird das Alltagsverhalten.
- Die Akkuausnahme für den Foreground-Service wird genauso gesetzt, wie sie das
  Produkt später anfordert. Die gewählte Einstellung wird in `run.meta`
  vermerkt und ist über alle Reihen gleich.
- Aus: Battery Saver (auch automatisch), Adaptive Battery, Play-Store-Auto-Update,
  Play-Protect-Scan, Konten-Sync, Standortdienste (Ausnahme siehe 4.5),
  „Ok Google"-Hotword, Always-On-Display, adaptive Helligkeit (Display ist aus,
  aber Sensorik läuft sonst mit).
- Keine OS- oder App-Updates während der Messkampagne. Flugmodus-Kontrollen
  (K1/K2) prüfen mit, dass keine Fremdlast dazwischenfunkt.

### 4.5 BLE-Umgebung (nur R4 relevant, aber reproduzierbar zu halten)
Der Empfangspfad kostet Strom, und er hängt davon ab, **wie viele Beacons in
Reichweite sind**. Ohne feste Vorgabe ist R4 nicht reproduzierbar.

- Fester Aufbau: genau **eine** Beacon-Gegenstelle in ~2 m Abstand, die im
  30-s-Raster sendet (zweites Gerät mit derselben App, als Kontakt eingerichtet).
- Messgeräte, die parallel R4 laufen lassen, **dürfen sich nicht gegenseitig
  sehen** — sonst ist die Nachbarschaftsdichte pro Gerät verschieden. Getrennte
  Räume oder zeitlich versetzt.
- Android verlangt für BLE-Scan je nach Version die Standortberechtigung und
  teils aktivierte Standortdienste. Wenn das nötig ist, gilt es für **alle**
  Reihen gleich und wird in `run.meta` vermerkt.
- Umgebungsfunk (fremde BLE-Geräte) grob protokollieren: Büro werktags ≠
  Wohnung nachts. Idealerweise alle Läufe am selben Ort.

### 4.6 Referenzprofil der App (festgelegt 2026-09-02)
Damit Läufe vergleichbar sind, ist der App-Zustand vor jedem Lauf identisch
herzustellen (Snapshot zurückspielen):

**P-REF, kriterientragend:**

| Größe | Festlegung | Begründung |
|---|---|---|
| Kompartimente | 5 | oberes Ende des Richtwerts 2–5 aus `gesamtkonzept.md` §2.2; jedes Kompartiment ist ein eigener Onion-Service mit eigenem Descriptor-Republish |
| Kontakte gesamt | 5 | Sync-Fenster und Beacon-Tokens skalieren damit; mindestens einer je Kompartiment |
| davon dauerhaft erreichbar | 1 | erzeugt echte Verbindungsversuche statt nur Warteschlange |
| offene Warteschlange | 0 Nachrichten | „Leerlauf" |
| Gruppen | 0 | Gruppen sind Phase 4, nicht Gegenstand von S5 |

**P-SKAL, berichtspflichtig, kein Kriterium:** R1 und R4 je einmal 24 h mit
20 Kontakten in denselben 5 Kompartimenten. Liefert die Steigung je Kontakt.
Kosten: zwei zusätzliche Läufe je Gerätemodell und ein zweiter App-Snapshot.

Die Zahlen sind eine Setzung des Entscheiders (`ops/autopilot/ENTSCHEIDUNGEN.md`,
Eintrag A4), keine Ableitung aus Messdaten. Sie sind mitzuberichten: ein Ergebnis
gilt nur für das Profil, unter dem es entstand.

### 4.7 Temperatur
- Umgebungstemperatur je Lauf notieren (`ambient_temp_c`), Ziel 20–25 °C,
  Schwankung über die Kampagne < 5 K. Warme Umgebung erhöht den Ruhestrom und
  bringt Throttling näher.
- Gerät frei liegend, nicht auf Textil, nicht gestapelt, nicht in der Sonne.
- Akkutemperatur und `thermalservice`-Status werden mitgeschrieben.

---

## 5. Messprinzip: kein Polling während des Laufs

Der naheliegende Weg — alle paar Minuten `adb shell dumpsys battery` abfragen —
**verfälscht die Messung**, weil jede adb-Abfrage das Gerät weckt und tiefe
Doze-Phasen verhindert. Über USB kommt hinzu, dass das Gerät dabei lädt.

Deshalb:

1. Verbindung ausschließlich über **WLAN-adb** (Wireless Debugging). Das Gerät
   hängt während der gesamten Kampagne an keinem Kabel.
2. Während des Laufs **keine** Abfragen. Das Gerät zeichnet den Füllstandsverlauf
   selbst auf (`dumpsys batterystats --history`).
3. Erst nach dem Lauf werden die Dumps geholt und die Kurve rekonstruiert
   (`s5-end-run.sh` → `s5-eval history`).
4. Die Entladerate wird per **linearer Regression über alle Füllstandswechsel**
   bestimmt, nicht aus Anfang minus Ende. Das drückt den Quantisierungsfehler
   der 1-%-Schritte deutlich.
5. Der Coulomb-Zähler (`Charge counter`, µAh) wird zusätzlich ausgewertet, wenn
   das Gerät ihn liefert — er ist feiner als der Prozentwert.

Der optionale Mitschnitt `s5-sample.sh` (Thermal-Verlauf, Screening) ist damit
ausdrücklich ein **Sonderweg**: Er darf nur verwendet werden, wenn sein
Eigenverbrauch über K3 beziffert ist und alle verglichenen Reihen ihn gleich
verwenden.

---

## 6. Zwischen zwei Läufen zurücksetzen

Checkliste, vollständig abzuarbeiten. Sie ist der Grund, warum Läufe überhaupt
vergleichbar sind.

1. Rohdaten des vorigen Laufs gesichert (`s5-end-run.sh` gelaufen).
2. Gerät auf 100 % laden, abstecken.
3. **Neustart** des Geräts. Danach **mindestens 20 min** Ruhe, damit der
   Boot-Nachlauf (Indexer, Medien-Scan, Play-Dienste) abklingt.
   `s5-precheck.sh` erzwingt das über die Uptime-Prüfung.
4. **Abkühlen** ≥ 60 min nach Ladeschluss; Akkutemperatur ≤ 32 °C.
5. App-Zustand auf den Referenz-Snapshot zurücksetzen (§4.6) — gleiche
   Kontaktzahl, gleiche Kompartimente, leere Warteschlange.
   Bei R0/R5: Vault deinstalliert bzw. der Referenz-Messenger im definierten
   Ausgangszustand.
6. Konfiguration der nächsten Reihe setzen (Snowflake an/aus, Shaping an/aus,
   BLE an/aus) und in `run.meta` unter `app_build`/`operator_note` festhalten.
7. `dumpsys batterystats --reset` (macht `s5-start-run.sh`).
8. `s5-precheck.sh` muss grün sein. Sonst wird nicht gestartet.

Nicht zurückgesetzt wird die Geräteidentität/Google-Konto-Einrichtung — der
Grundzustand soll über die ganze Kampagne konstant bleiben.

---

## 7. Reihenfolge und Gegenbalancierung

Reihenfolge ist keine Nebensache: Umgebungstemperatur, Wochentag und
Akku-Alterung driften über die Kampagne. Würde jedes Gerät die Reihen in
derselben Folge fahren, ginge die Drift direkt in die Differenzen ein.

- Jedes Gerät fährt alle Reihen, aber in **unterschiedlicher Reihenfolge**
  (lateinisches Quadrat). Beispiel für 3 baugleiche Einheiten:

| Tag | Einheit 1 | Einheit 2 | Einheit 3 |
|---|---|---|---|
| 1 | R0 | R3 | R5 |
| 2 | R1 | R4 | R0 |
| 3 | R2 | R5 | R1 |
| 4 | R3 | R0 | R2 |
| 5 | R4 | R1 | R3 |
| 6 | R5 | R2 | R4 |
| 7 | R0 | R3 | R5 |
| 8 | R1 | R4 | R0 |
| … | … | … | … |

- Baseline R0 wird **nicht** einmal am Anfang gemessen und dann für alles
  wiederverwendet, sondern über die Kampagne verteilt. Driftet R0 zwischen
  erster und letzter Wiederholung um mehr als die halbe Kriterienschwelle
  (> 4 %/24 h bei K-A, > 1 %/24 h bei K-B), ist die Umgebung nicht stabil und
  die Kampagne wird nicht ausgewertet, sondern korrigiert.
- Wiederholungen derselben Reihe möglichst an verschiedenen Wochentagen.

---

## 8. Wie viele Wiederholungen — und warum

### 8.1 Entscheidungsregel
Ein Mittelwert allein trägt keine Gate-Entscheidung. Entschieden wird über das
**einseitige 95-%-Konfidenzintervall der Differenz** zweier Reihen (Welch,
ungleiche Varianzen):

| Lage des Intervalls | Urteil |
|---|---|
| ganz **unter** der Schwelle (obere Grenze < Schwelle) | Kriterium **bestanden** |
| ganz **über** der Schwelle (untere Grenze > Schwelle) | Kriterium **gerissen** |
| Schwelle liegt **im** Intervall | **unentschieden** → mehr Läufe |

Das ist bewusst streng: Ein Punktschätzer von 7,8 %/24 h mit ±1,5 %
Unsicherheit ist kein bestandenes 8-%-Kriterium.

### 8.2 Mindestzahl
- **n = 3 gültige Läufe je Reihe und Gerätemodell** als Untergrenze. Mit n = 2
  ist die Streuung praktisch nicht schätzbar (t-Quantil bei df = 1 ist 6,31 —
  das Intervall wird so breit, dass fast jedes Ergebnis unentschieden bleibt).
- **Sequenzielle Regel:** Nach n = 3 auswerten. Ist ein Kriterium unentschieden,
  weitere Läufe nachfahren, bis es entschieden ist — **Obergrenze n = 5**.
  `s5-eval` rechnet aus der beobachteten Streuung aus, wie viele Läufe je Reihe
  nötig wären, und gibt die Zahl aus.
- Ist ein Kriterium bei n = 5 immer noch unentschieden, ist das **das Ergebnis**:
  Der Verbrauch liegt zu nah an der Schwelle, um ihn mit dieser Methode zu
  trennen. Dann greift die Fallback-Kaskade der Spec, nicht ein weiterer Lauf.

Die nötige Laufzahl aus der Streuung vorab zu berechnen, ist hier nicht möglich:
Es gibt keine belastbare Vorab-Streuung für diese Geräte und diese App. Genau
deshalb die sequenzielle Regel statt einer geratenen Fallzahl.

### 8.3 Geräte
- Mindestens **2 verschiedene Modelle** (`spec/phase0-spikeplan.md` §2 spricht von
  „Referenzgeräten", Plural). Ein AOSP-nahes Gerät und ein OEM-Gerät mit
  aggressivem Hersteller-Energiemanagement — das ist der realistische
  Schlechtfall für einen Foreground-Service.
- **%/24 h ist nicht zwischen Modellen mittelbar** (verschiedene Kapazität und
  Grundlast). Jedes Modell wird eigenständig ausgewertet; das Gesamturteil ist
  der schlechteste Einzelfall. `s5-eval verdict` macht genau das.

### 8.4 Kalenderrechnung — und der Konflikt mit der Timebox
Je Gerätemodell: 6 Reihen × 3 Läufe + 3 Kontrollreihen × 2 = **24 Läufe**.
Je Lauf: 24 h Messfenster + ~4 h Rüstzeit (Laden, Abkühlen, Neustart, Settle,
Dumps) ≈ **28 h**.

- 24 × 28 h ≈ **28 Gerätetage je Modell**.
- Auf **einer** Einheit: ~4 Wochen. Die Timebox von 8 T ist dann **gerissen**,
  bevor die erste Auswertung steht.
- Mit **4 baugleichen Einheiten** je Modell parallel: ~7 Kalendertage.
- Zwei Modelle parallel erfordern damit **8 Geräte**.

Das ist ein Beschaffungsproblem, kein Messproblem — und es muss **vor** dem
Kampagnenstart entschieden sein. Realistische Optionen:

| Option | Geräte | Kalenderzeit | Was man verliert |
|---|---|---|---|
| A | 8 (2 Modelle × 4) | ~7 Tage | nichts, voller Umfang |
| B | 4 (1 Modell × 4) | ~7 Tage | Modellvielfalt; OEM-Schlechtfall ungeprüft |
| C | 2 (2 Modelle × 1) | ~4 Wochen | Timebox |
| D | 8 (2 Modelle × 4), aber n = 2 statt 3 | ~5 Tage | Entscheidbarkeit (siehe 8.2) |

Option D ist nur scheinbar günstig: Mit n = 2 wird das Intervall so breit, dass
die Kriterien überwiegend unentschieden bleiben. Empfehlung: A, ersatzweise B.

### 8.5 Screening in Woche 3 (Frühindikator R-2)
`spec/phase0-spikeplan.md` §6 verlangt als Frühindikator eine „S5-Erstmessung
Woche 3". Dafür genügt ein verkürzter Durchgang:

- Reihen R0, R1, R4, je 1 Lauf, je **6 h** (`s5-eval run --min-hours 6`).
- Diese Läufe sind **nicht Gate-tauglich** und werden nie als Kriterienbeleg
  zitiert: 6 h erfassen die tiefen Doze-Phasen nicht, die erst über Nacht
  entstehen; die Hochrechnung auf 24 h überschätzt systematisch. `s5-eval`
  markiert solche Läufe als `[hochgerechnet]`.
- Zweck ist allein die Frühwarnung: Liegt die Größenordnung völlig daneben,
  wird die Fallback-Kaskade sofort geplant statt in Woche 8.

---

## 9. Was einen Lauf ungültig macht

`s5-eval` verwirft automatisch und nennt den Grund:

| Prüfung | Grenze |
|---|---|
| Gerät am Ladegerät | jedes `plugged=1` |
| Display an | jedes `screen_on=1` |
| Laufdauer | < 20 h (Gate-Läufe) |
| Startfüllstand | außerhalb 88–97 % |
| Endfüllstand | < 25 % |
| Messpunkte | < 8 |
| Linearität der Entladekurve | r² < 0,90 |
| Füllstandssprung nach oben | > 0,5 Prozentpunkte |

Zusätzlich vom Menschen zu verwerfen (Werkzeug kann es nicht sehen):
OS-/App-Update während des Laufs, Ortswechsel, ungeplante Nutzung, Fremdgerät
mit BLE-Dauersendung in Reichweite, Heizung/Sonne am Ablageort.

---

## 10. Ablauf je Lauf

```sh
# einmalig
cargo build --release --manifest-path spikes/S5/tools/s5-eval/Cargo.toml
sh spikes/S5/tools/smoke-test.sh          # Trockenlauf ohne Geraet

# je Lauf
export S5_SERIAL=192.168.1.42:5555        # WLAN-adb, kein USB
export S5_DEVICE_LABEL=DEV-A              # Label, nicht die Seriennummer

sh spikes/S5/tools/collect/s5-precheck.sh
sh spikes/S5/tools/collect/s5-start-run.sh R3 01 spikes/S5/runs
#   -> run.meta ausfuellen: design_capacity_uah, ambient_temp_c,
#      wifi_rssi_dbm, app_build, operator_note

# ... 24 h nichts tun ...

sh spikes/S5/tools/collect/s5-end-run.sh spikes/S5/runs/R3/DEV-A-R3-01

# nach der Kampagne
spikes/S5/tools/s5-eval/target/release/s5-eval verdict spikes/S5/runs
```

`s5-eval verdict` gibt je Gerät die Reihenmittelwerte, die Zwischenschritte
(R1−R0, R2−R1, R3−R2, R4−R3, R5−R0) und die vier Kriterien K-A1, K-A2, K-B, K-C
aus. Exitcode: 0 = alle bestanden, 1 = mindestens eines gerissen,
2 = unentschieden/zu wenig Daten.

Zusätzlich je Lauf sinnvoll:

```sh
s5-eval batterystats <lauf>/raw-batterystats-checkin.txt   # Zuordnung: wohin geht der Strom
s5-eval thermal      <lauf>/raw-thermalservice.txt         # Throttling-Pruefung
```

Battery Historian (optional, für die Zeitachse eines auffälligen Laufs):
`S5_BUGREPORT=1 sh s5-end-run.sh …` erzeugt `bugreport.zip`, das lokal in einer
Historian-Instanz geöffnet wird.

---

## 11. Datenhygiene

- Der Bugreport enthält sehr viel Gerätekontext (Paketnamen, WLAN-Namen, Logs).
  Er bleibt **lokal**, kommt nicht ins Repo und wird nicht weitergegeben
  (CLAUDE.md: keine Schlüssel, Onion-Adressen, Kontakt-IDs nach außen; ADR-14:
  kein Telemetrie-Kanal).
- Gemessen wird mit einer **Wegwerf-Identität** ohne echte Kontakte. Die
  Referenzkontakte sind andere Messgeräte.
- Die Skripte lesen ausschließlich Systemzähler, nie App-Daten. Als
  Gerätebezeichner dient ein frei gewähltes Label (`DEV-A`), nicht die
  Seriennummer.
- In `runs/` gehören Sample-CSV, Dumps und `run.meta` — keine Screenshots,
  keine Chatinhalte.

---

## 12. Protokollbogen je Lauf

`run.meta` wird von `s5-start-run.sh` automatisch angelegt und um Endwerte
ergänzt. Von Hand nachzutragen:

```
# design_capacity_uah=      Nennkapazitaet in uAh (Datenblatt)
# ambient_temp_c=           Umgebungstemperatur
# wifi_rssi_dbm=            Signalstaerke am Ablageort
# app_build=                Commit/Build der gemessenen App
# operator_note=            Reihe, Aufbau, Besonderheiten
```

Zusätzlich in einem Kampagnenprotokoll festhalten: Gerätemodell, Android-Build,
Akkugesundheit/Ladezyklen (falls auslesbar), Aufstellort, Anzahl fremder
BLE-Geräte in Reichweite, wer den Lauf betreut hat.
