# Spike S2 — Multi-Device-Ratchet-Sync · Bericht

**Frage (`spec/phase0-spikeplan.md` §2):** „Funktioniert paarweiser
Double-Ratchet-Sync zwischen eigenen Geraeten robust, oder braucht es ein
Primaergeraet-Modell?"

**Ergebnis in einem Satz:** Variante A (geteilte Kontakt-Session mit
`dr_delta`-Replikation nach `protokoll-spec.md` §9.3) verliert in 10.000
randomisierten Laeufen **4,151 %** aller Nachrichten dauerhaft; Variante B
(Primaergeraet) verliert in denselben 10.000 Laeufen **0** Nachrichten und
erzeugt **0** Duplikate. **Empfehlung: Fallback — Primaergeraet-Modell.**

---

## 0. Was echt ist und was modelliert ist

Das ist keine Feldmessung, sondern eine **Modellsimulation**. Die Trennlinie:

| Ebene | Status |
|---|---|
| X25519 (DH) | **echt** — `x25519-dalek` 2.0 |
| HKDF-SHA-256 (`KDF_RK`) | **echt** — `hkdf` 0.12 / `sha2` 0.10 |
| HMAC-SHA-256 (`KDF_CK`) | **echt** — `hmac` 0.12 |
| XChaCha20-Poly1305 (AEAD) | **echt** — `chacha20poly1305` 0.10 |
| BLAKE3 (`H(x)`, `msg_id`) | **echt** — `blake3` 1.x |
| Double-Ratchet-Zustandsautomat | **echt, aber vendort**: crate `double-ratchet` 0.1.0 (BSD-3-Clause), Datei `src/dr.rs` Z. 1–701, unveraendert bis auf additive Instrumentierung (Aenderungen im Kopf von `src/vendor_dr.rs` einzeln aufgelistet). Enthaelt `MAX_SKIP = 1000` und `MKS_CAPACITY = 2000`. |
| PQXDH-Handshake (ML-KEM) | **nicht ausgefuehrt** — die Session wird direkt aus einem gemeinsamen Geheimnis initialisiert. Fuer die Fragestellung irrelevant, aber es ist keine Aussage ueber PQXDH. |
| Tor-Transport, Onion-Aufbau, HSDir | **modelliert** — Einwegverzoegerung gleichverteilt 1,5–7,5 s, plus transiente Verbindungsfehler (`p_flap` 0,10 / 0,35 je Profil) |
| Erreichbarkeit der Geraete | **modelliert** — zufaellige Duty-Cycles plus Sync-Fenster nach §10 |
| Uhr-Drift | **modelliert** — statischer Offset je Geraet, ±10 min im Drift-Profil |
| Speicher, Akku, SQLCipher, FFI | **nicht modelliert** |
| Boesartiges Verhalten (A4/A7) | **nicht modelliert** — der Kontakt ist ehrlich |

**Wichtigste Modellierungsentscheidung — und sie faellt zugunsten von
Variante A aus:** Damit mehrere eigene Geraete dieselbe Session fortfuehren
koennen, muss der private DH-Ratchet-Schluessel geteilt sein. Die Simulation
leitet ihn kanonisch als `H(Sitzungs-Seed ‖ dhr_pub)` ab. Damit ist die
Replikation privater Ratchet-Schluessel **verlustfrei und
verzoegerungsfrei** — besser, als es real je sein koennte. Alle unten
gemessenen Fehler von Variante A treten also **trotz** idealer
Schluesselreplikation auf. Der Kontrolltest
`echte_zufallsschluessel_zerstoeren_die_session_dauerhaft` zeigt, was ohne
diese Idealisierung passiert: das zweite Geraet kann die Session danach
**dauerhaft** nicht mehr benutzen.

**Zeitmodell:** Die Uhr ist simuliert (Einheit ms); es wird nie real
gewartet. Abbildung auf reale Zeit 1:1 — „60 s" im Kriterium sind 60.000
simulierte Millisekunden. Ein Lauf umfasst 14 simulierte Tage Szenario plus
2 Tage Drain-Phase; „wochenlang offline" ist ein Loch von 7–13 simulierten
Tagen im Zeitplan eines Geraets. Der Geschwister-Sync kostet 1 Verbindung
(Latenz wie oben) plus 10 ms je SyncRecord — das entspricht ~512 B bei
~50 kB/s ueber einen Onion-Stream. **Diese 10 ms sind eine Annahme, keine
Messung**; S1 liefert den realen Wert.

---

## 1. Aufbau

- Kontakt sendet **1.000 Nachrichten** je Lauf, in 8–40 Gespraechsbuendeln
  ueber 10 simulierte Tage, Zustellreihenfolge zufaellig (der Sender waehlt
  aus seiner Warteschlange zufaellig, das Netz ordnet zusaetzlich um).
- **2 oder 3** eigene Geraete (je Lauf zufaellig).
- Zielreihenfolge deterministisch (§9.2), Ack-Timeout 60 s, persistente
  Ausgangswarteschlange mit dem **fertig verschluesselten** Envelope
  (`gesamtkonzept.md` §2.6 Punkt 1), Abbruch nach 30 Versuchen
  (Sensitivitaet siehe §6).
- `DELIVERED` wird **ausschliesslich** gesetzt, nachdem der Kontakt ein
  entschluesseltes `Ack` mit passender Nachrichten-ID gelesen hat
  (`protokoll-spec.md` §9.4, `CLAUDE.md`). Es gibt im Code genau eine
  Stelle, die das Flag setzt.
- Fuenf Szenarioprofile, gleichverteilt ueber die Laeufe: `concurrent`,
  `long-offline`, `partition-mid-ratchet`, `clock-drift`, `mixed`.
- Seeds fest; **dieselben Seeds erzeugen fuer alle Varianten dieselben
  Szenarien** (gleiche Zeitplaene, gleiche Nachrichtenzeitpunkte).

Kontrolle der Krypto-Schicht: 8 Unit-Tests, alle gruen
(`cargo test --release`): Round-Trip, Out-of-Order mit exakt 499 Skipped
Keys, `MAX_SKIP`-Grenze bei 1001, Replay-Abweisung, Determinismus zweier
Zustandsreplikate, Divergenzerkennung, sowie die beiden Tests, die den
Kernbefund isolieren.

---

## 2. Kriterium 1 — 0 Verluste, 0 Duplikate in 10.000 Laeufen

> „0 Nachrichtenverluste, 0 Duplikate in 10.000 randomisierten Laeufen"

*Verlust* = Nachricht liegt am Simulationsende auf **keinem** eigenen Geraet.
*Konvergenzluecke* = Nachricht liegt auf mindestens einem, aber nicht auf
allen Geraeten. *Echtes Duplikat* = doppelte Zustellung, die
`msg_id = H(dr_header ‖ ciphertext)` nach §8 **nicht** erkennen kann.

| Variante | Laeufe | Nachrichten | Verluste | Verlust % | echte Duplikate | Dup % | Konvergenz&shy;luecken | fehlerfreie Laeufe |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **A** (§9.3 woertlich) | 10.000 | 10.000.000 | **415.090** | **4,151 %** | 0 | 0,0000 % | 0 | 3.488 / 10.000 |
| **A-reconcile** | 600 | 600.000 | **71.162** | **11,860 %** | 0 | 0,0000 % | 0 | 399 / 600 |
| **B** (Primaergeraet) | 10.000 | 10.000.000 | **0** | **0,000 %** | **0** | 0,0000 % | **0** | **10.000 / 10.000** |
| A2 (Session je Geraet, informativ) | 10.000 | 10.000.000 | 0 | 0,000 % | **19.865** | **0,1986 %** | 0 | 4.126 / 10.000 |

Doppelte Zustellungen insgesamt (also inkl. der von §8 erkennbaren):
A 10.212 · A-reconcile 13.310 · **B 0** · A2 33.070 (davon 19.865 nicht
erkennbar).

Verlust je Szenarioprofil (Variante A, je 2.000 Laeufe):

| Profil | Verlust % (A) | Verlust % (B) |
|---|---:|---:|
| `clock-drift` | 5,550 % | 0,000 % |
| `partition-mid-ratchet` | 5,457 % | 0,000 % |
| `long-offline` | 3,954 % | 0,000 % |
| `mixed` | 3,814 % | 0,000 % |
| `concurrent` | 1,979 % | 0,000 % |

Nach Geraetezahl: A verliert mit 2 Geraeten 3,723 %, mit 3 Geraeten
4,574 %. A-reconcile: 8,425 % bzw. 14,927 %. B: 0,000 % in beiden Faellen.

**Kriterium 1: A und A-reconcile gescheitert. B bestanden. A2 gescheitert
(Duplikate).**

---

## 3. Kriterium 2 — Konvergenz < 60 s nach Wiederverbindung

> „Konvergenz < 60 s nach Wiederverbindung"

Gemessen wird je Wiederverbindung eines Geraets nach ≥ 1 h Offline-Zeit die
Zeit bis zur vollstaendigen Uebernahme des Verlaufs der Geschwister —
**gerechnet ab dem Zeitpunkt, zu dem erstmals ein datenhaltendes
Geschwistergeraet gleichzeitig online ist.** Ab dem blossen
Wiederverbindungszeitpunkt zu messen waere sinnlos: serverlos gibt es keinen
Zwischenspeicher, ein allein wiederverbundenes Geraet kann nichts holen.

| Variante | Sonden | < 1 s | < 5 s | < 15 s | < 60 s | < 300 s | < 1 h | ≥ 1 h | **Anteil < 60 s** | max |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| A | 32.027 | 27 | 12.161 | 14.315 | 3.191 | 248 | 1.059 | 1.026 | **92,72 %** | 946.234 s |
| A-reconcile | 2.433 | 38 | 627 | 1.297 | 191 | 91 | 93 | 96 | **88,49 %** | 761.347 s |
| **B** | 30.021 | 0 | 12.922 | 14.272 | 630 | 186 | 1.008 | 1.003 | **92,68 %** | **18.067 s** |
| A2 | 48.127 | 2 | 19.127 | 24.300 | 418 | 370 | 1.744 | 2.166 | **91,11 %** | 1.069.797 s |

**Das Kriterium wird in ~93 % der Wiederverbindungen erfuellt, aber nicht
universell — und zwar bei allen Varianten gleichermassen.** Die Ursache ist
nicht die Multi-Device-Architektur, sondern das serverlose Zustellmodell:

- Der Verlauf liegt verteilt; Konvergenz braucht **jedes** datenhaltende
  Geschwistergeraet, nicht nur eines.
- Ein Sync-Fenster nach §10 ist 180 s lang. Ein grosser Rueckstand passt
  nicht in ein Fenster; die Uebertragung setzt im naechsten fort.

Der lange Schwanz (≥ 1 h: A 3,20 %, B 3,34 %, A2 4,50 %) besteht aus genau
diesen Faellen. Bei Variante B ist der Maximalwert mit 5,0 h ~52-mal kleiner
als bei A (11,0 Tage) — bei A haengen Sonden fest, weil Nachrichten
tatsaechlich verloren sind und nie ankommen.

**Kriterium 2: von keiner Variante universell erfuellt; B ist die einzige,
deren Schwanz nicht durch Datenverlust verursacht ist. Das Kriterium ist so,
wie es formuliert ist, unter Serverlosigkeit nicht erreichbar und muss
umformuliert werden (siehe §7, Punkt 3).**

---

## 4. Kriterium 3 — `skipped_message_keys` < 1000 pro Session

> „`skipped_message_keys` < 1000 pro Session (Speicherobergrenze)"

Gemessen wird der ueber den Lauf maximale Fuellstand des Skipped-Key-Speichers.

**Auf eigenen Geraeten:**

| Variante | p50 | p95 | p99 | max | Laeufe ≥ 1000 | `SkipTooLarge`/`StorageFull` |
|---|---:|---:|---:|---:|---:|---:|
| A | 78 | 173 | 248 | 947 | **0** | 0 |
| A-reconcile | 68 | 307 | 611 | 857 | **0** | 0 |
| **B** | 55 | 115 | 150 | **255** | **0** | 0 |
| A2 | 34 | 83 | 106 | 208 | **0** | 0 |

**Auf der Kontaktseite** (auch eine Session, daher mitgemessen):

| Variante | p50 | p95 | p99 | p99,9 | max | Laeufe ≥ 1000 |
|---|---:|---:|---:|---:|---:|---:|
| A | 29 | 152 | 940 | 1.940 | **2.000** (Kappungsgrenze erreicht) | 92 / 10.000 (0,92 %) |
| A-reconcile | 23 | 123 | 1.157 | 1.962 | 1.962 | 7 / 600 (1,17 %) |
| **B** | 305 | 458 | 609 | 995 | **1.220** | **8 / 10.000 (0,08 %)** |
| A2 | 21 | 47 | 62 | 83 | 121 | 0 / 10.000 |

**Kriterium 3: auf eigenen Geraeten von allen Varianten erfuellt (B mit
grossem Abstand: max 255). Auf der Kontaktseite ueberschreitet B die 1000 in
0,08 % der Laeufe (Spitze 1.220), ohne dass daraus ein Verlust entstuende.**
Ursache bei B: das Primaergeraet quittiert einen weitergeleiteten Stapel
gebuendelt, die Acks treffen stark umgeordnet ein. Das ist ueber die
Ack-Taktung steuerbar (Implementierungsparameter), nicht strukturell.
Variante A erreicht auf der Kontaktseite in 0,92 % der Laeufe die harte
Kappungsgrenze von 2.000 — dort werden Acks nicht mehr angenommen.

---

## 5. Aufwand und Zustellstatus (Nebenbefunde, nicht Kriterium)

| Variante | SyncRecords je Nachricht | Zustellversuche je Nachricht | vom Kontakt verworfene Acks | erkannte Sendeketten-Divergenzen | fehlgeschlagene Entschluesselungen |
|---|---:|---:|---:|---:|---:|
| A | 3,50 | 3,62 | 4.159.750 | 20.437.171 | 22.512.510 |
| A-reconcile | 22,13 | 17,56 | 7.726.794 | 9.140.599 | 2.525.874 |
| **B** | **1,50** | **2,81** | **1.450** | **0** | **0** |
| A2 | 1,51 | 1,00 | 0 | 0 | 0 |

Variante A entschluesselt im Mittel **2,25-mal je Nachricht vergeblich** und
verwirft **0,42 Acks je Nachricht**. Das ist kein Randphaenomen, sondern der
Normalbetrieb.

Zustellstatus (§9.4): B markiert 9.999.927 von 10.000.000 Nachrichten als
`DELIVERED`; **73** (0,0007 %) bleiben bis zum Simulationsende `WAITING` —
ehrlich, nie faelschlich „zugestellt". A markiert 9.454.477; 545.523 bleiben
`WAITING`.

---

## 6. Sensitivitaet

**Wiederholungsobergrenze** (je 1.000 Laeufe, identische Seeds, Variante A):

| Obergrenze | Verluste | Verlust % |
|---|---:|---:|
| 30 Versuche | 38.555 | 3,856 % |
| 200 Versuche | 6.339 | 0,634 % |

Ein grosszuegigeres Wiederholungsbudget verkleinert den Verlust von A um den
Faktor 6, beseitigt ihn aber **nicht**. Der Rest ist strukturell: ein
Envelope, dessen Message Key auf dem Zielzweig verbraucht oder dessen
Wurzelschluessel divergiert ist, wird durch Wiederholung nie lesbar. B bleibt
in beiden Einstellungen bei 0.

**Latenz ×3** (Einwegverzoegerung 4,5–22,5 s):

| Variante | Laeufe | Verlust % | echte Duplikate % | skipMax Geraet | Kontaktseite ≥ 1000 |
|---|---:|---:|---:|---:|---:|
| A | 1.000 | 3,925 % | 0 % | 333 | 2,30 % der Laeufe |
| **B** | 2.000 | **0,000 %** | **0 %** | 250 | 1,85 % der Laeufe |
| A2 | 2.000 | 0,000 % | **0,647 %** (statt 0,199 %) | 192 | 0 % |

B bleibt bei dreifacher Latenz verlustfrei. A2 verschlechtert sich deutlich:
mehr Wiederholungen ⇒ mehr Neuverschluesselungen fuer ein anderes Zielgeraet
⇒ mehr Duplikate. Der Skipped-Key-Druck auf der Kontaktseite steigt bei
beiden Varianten mit der Latenz — das ist der Parameter, der die 1000er-Grenze
tatsaechlich bestimmt.

---

## 7. Befunde

**F-1 — Der Double Ratchet ist ein Zwei-Parteien-Protokoll. Sein Sendezustand
ist nicht replizierbar.**
`protokoll-spec.md` §2 sieht **eine** Session je Kontakt vor, §9.3 verlangt,
dass **jedes** empfangende Geraet quittiert („persist(pt); send Ack"). Damit
senden zwangslaeufig mehrere Geraete auf derselben Session. Folgen, im
Kontrolltest `parallele_sender_verlieren_das_zweite_ack` isoliert
nachgewiesen:

1. Zwei Geraete belegen dieselbe Kettenposition `(dh_pub, n)`. Der Kontakt
   liest genau einen der beiden Envelopes; der zweite ist **dauerhaft
   unlesbar**, weil der Message Key nach Gebrauch geloescht wird — exakt die
   Forward-Secrecy-Eigenschaft, die das Design will.
2. Ohne die guenstige Modellannahme (geteilte Ratchet-Schluessel) divergiert
   der **Wurzelschluessel**; das betroffene Geraet kann die Session danach
   dauerhaft nicht mehr benutzen (Test
   `echte_zufallsschluessel_zerstoeren_die_session_dauerhaft`).
3. Damit A ueberhaupt funktionieren koennte, muessten **private
   Ratchet-Schluessel** ueber `dr_delta` zwischen Geraeten wandern. Das hebt
   die Post-Compromise-Security fuer die gesamte Geraetemenge auf.

Die in §9.3 skizzierte Reconciliation loest das nicht: DH-Ratchet-Schritte
sind nicht kommutativ, ein Zustandssnapshot ist beim Eintreffen veraltet.
Gemessen: A-reconcile ist mit 11,860 % Verlust fast dreimal schlechter als A.
**Jede korrekte Reconciliation muss die Sendevorgaenge serialisieren — und ist
damit das Primaergeraet-Modell.**

**F-2 — `msg_id` nach §8 taugt nicht als geraeteuebergreifender
Dedup-Schluessel.**
`msg_id = H(dr_header ‖ ciphertext)` aendert sich, sobald dieselbe Nachricht
neu verschluesselt wird. Bei A und B faellt das nicht auf, weil die
Ausgangswarteschlange den fertigen Envelope haelt. Bei A2 (Session je
Geraet) muss der Sender fuer ein anderes Zielgeraet neu verschluesseln —
Ergebnis: 19.865 echte Duplikate in 10 Mio. Nachrichten (0,199 %), bei
dreifacher Latenz 0,647 %.

**F-3 — Ohne Envelope-Cache ist das Zustellmodell nicht abschliessbar.**
Geht ein Ack verloren und der Sender stellt denselben Envelope erneut zu,
kann der Empfaenger ihn **nicht mehr entschluesseln** — der Message Key ist
verbraucht. Ohne Gegenmassnahme laeuft das Paar in eine Endlosschleife:
Sender wiederholt, Empfaenger kann nicht quittieren. Die Simulation fuehrt
deshalb in **allen** Varianten je Session einen Cache `H(Envelope) → msg_id`
und beantwortet einen wiederholten Envelope mit einem **frisch
verschluesselten** Ack. Das ist eine notwendige Protokollergaenzung, die in
§9.2/§9.3 fehlt.

**F-4 — Das Konvergenzkriterium ist so nicht erreichbar.**
„Konvergenz < 60 s nach Wiederverbindung" setzt voraus, dass beim
Wiederverbinden jemand da ist, von dem man synchronisieren kann. Serverlos
ist das nicht garantiert. Messbar und sinnvoll ist: „< 60 s, **nachdem ein
datenhaltendes Geschwistergeraet erreichbar ist**". Dieses Kriterium wird zu
92,7 % erfuellt; der Rest sind Faelle, in denen mehrere Geschwister Daten
halten oder ein 180-s-Sync-Fenster fuer den Rueckstand nicht reicht.

**F-5 — Variante B kostet Zustelllatenz, aber keine Korrektheit.**
B braucht 2,81 Zustellversuche je Nachricht (A2: 1,00), weil ein Zweitgeraet
nicht quittieren kann und der Kontakt bis zur Weiterleitung ans Primaergeraet
`WAITING` bleibt. 73 von 10 Mio. Nachrichten (0,0007 %) blieben bis
Simulationsende unquittiert. Das ist der Preis und er ist bezahlbar —
`CLAUDE.md` Prioritaet 3 ist ausdruecklich opferbar.

---

## 8. Bewertung gegen die Erfolgskriterien

| Kriterium | A | A-reconcile | **B** | A2 |
|---|:--:|:--:|:--:|:--:|
| 0 Verluste in 10.000 Laeufen | ✗ 4,151 % | ✗ 11,860 % | **✓ 0** | ✓ 0 |
| 0 Duplikate in 10.000 Laeufen | ✓ 0 | ✓ 0 | **✓ 0** | ✗ 0,199 % |
| Konvergenz < 60 s | ✗ 92,72 % | ✗ 88,49 % | **✗ 92,68 %** | ✗ 91,11 % |
| `skipped_message_keys` < 1000 (Geraet) | ✓ max 947 | ✓ max 857 | **✓ max 255** | ✓ max 208 |
| `skipped_message_keys` < 1000 (Kontakt) | ✗ 0,92 % ≥ 1000 | ✗ 1,17 % | **~ 0,08 %** | ✓ 0 |

## 9. Empfehlung

**Fallback — Primaergeraet-Modell (Variante B).**

Nicht „gescheitert": der Spike hat seinen Zweck erfuellt und ermoeglicht eine
klare Entscheidung. Nicht „bestanden": der in `protokoll-spec.md` §9.3
beschriebene Entwurf ist gemessen untauglich, und das im Spikeplan genannte
Konvergenzkriterium ist von keiner Variante universell erfuellbar.

Begruendung in der Reihenfolge des Prioritaetsstacks:

1. **Anonymitaet/Datenschutz:** B haelt Sitzungsschluessel auf **einem**
   Geraet statt auf allen. Variante A haette private Ratchet-Schluessel
   ueber alle eigenen Geraete verteilt und die Post-Compromise-Security fuer
   die gesamte Geraetemenge aufgehoben. Gegenbuchung: B erzeugt gegenueber
   einem autorisierten Kontakt ein feineres Praesenzsignal (Details im
   ADR-Entwurf, Abschnitt „Auswirkung auf das Threat Model").
2. **Serverlosigkeit:** unberuehrt. Das Primaergeraet ist ein Geraet des
   Nutzers, kein Dritter, kein Betreiber.
3. **Alles andere:** B kostet Latenz und macht ein Zweitgeraet ohne
   erreichbares Primaergeraet nicht sendefaehig. Genau das ist laut
   Prioritaetsstack opferbar.

Variante A2 (Session je Geraet) erfuellt Verlust- und Konvergenzkriterium
ebenso, faellt aber am Duplikat-Kriterium durch und verlangt, dass der Sender
**Klartext** in der Ausgangswarteschlange haelt — im Widerspruch zu
`gesamtkonzept.md` §2.6 Punkt 1 und zu ADR-13. Mit einer stabilen,
senderseitig vergebenen Nachrichten-ID waere A2 reparierbar; das ist eine
Aenderung an §8 und gehoert in einen eigenen ADR. **Hier wird das nicht
entschieden**, sondern als moeglicher spaeterer Migrationspfad vermerkt.

Der ADR-Entwurf liegt in `spikes/S2/adr-entwurf-GATE-2.md`.

---

## 10. Was nicht geprueft werden konnte — und warum

1. **Kein echtes Tor.** Latenzen, Verbindungsfehler und Erreichbarkeit sind
   Annahmen. Die realen Werte liefern erst S1 (Onion-Aufbau) und S5
   (Erreichbarkeit im Dauerbetrieb). Bis dahin gilt die Latenz-Sensitivitaet
   aus §6 als Absicherung: B bleibt bis ×3 verlustfrei.
2. **Kein echtes Geraet.** Kein SQLCipher, kein Keystore, kein Akku, keine
   Prozesslebenszyklen (Android-Foreground-Service). Der Speicherbedarf der
   Skipped Keys wurde in Anzahl, nicht in Bytes gemessen.
3. **Kein PQXDH.** Die Session startet aus einem gemeinsamen Geheimnis;
   ML-KEM-768 wurde nicht ausgefuehrt. Der Spike sagt nichts ueber den
   Handshake aus.
4. **Der Ratchet ist nicht die spaetere Produktionsbibliothek.** Vendort
   wurde `double-ratchet` 0.1.0 (2019, unmaintained). `MAX_SKIP = 1000` und
   `MKS_CAPACITY = 2000` sind dort fest verdrahtet und passen zufaellig genau
   zum Kriterium. Eine andere Implementierung (z. B. `vodozemac` mit 40
   Skipped Keys je Kette) wuerde die Zahlen aus §4 deutlich verschieben. Die
   Wahl der Produktionsbibliothek ist ein eigener Entscheidungspunkt.
5. **„Echtes" Variante A ist nicht messbar.** A wurde unter der guenstigsten
   Annahme simuliert (kanonisch abgeleitete Ratchet-Schluessel). Ohne diese
   Annahme ist A nicht implementierbar, ohne private Ratchet-Schluessel zu
   replizieren. Die reale Verlustrate von A liegt also **ueber** 4,151 %; wie
   weit darueber, ist nicht gemessen.
6. **Nur zwei Reconciliation-Strategien.** „Snapshot vom kanonischen Geraet"
   und „kein Snapshot". Dass keine dritte Strategie funktioniert, ist ein
   analytisches Argument (Nicht-Kommutativitaet der DH-Ratchet-Schritte),
   kein Messergebnis.
7. **Kein boesartiger Kontakt.** A4 (uebernommener Kontakt) und A7 (aktiver
   Netzangreifer) sind nicht modelliert. Ein Kontakt, der gezielt an zwei
   Geraete gleichzeitig zustellt, wuerde Variante A schlechter aussehen
   lassen — die gemessenen Werte sind also eine **untere** Schranke fuer den
   Schaden.
8. **Keine Gruppen.** `gruppen-spec.md` und §12 sind ausgeklammert. Wie sich
   MLS-Epochen zu einem Primaergeraet verhalten, ist offen und beruehrt G1.
9. **Kein Mesh als Geschwisterkanal.** §13 (BLE/Wi-Fi Direct) wurde nicht
   getrennt modelliert; Geschwister-Sync nutzt dieselbe Latenzannahme wie
   Tor. Real waere Mesh schneller und wuerde die Konvergenzzahlen aus §3
   verbessern.
10. **Ungleiche Laufzahlen.** 10.000 Laeufe fuer A, B und A2 wie gefordert.
    A-reconcile nur **600** Laeufe (600.000 Nachrichten): diese Variante
    kostet 173 s je 100 Laeufe (gegenueber 1,8 s bei B), 10.000 Laeufe waeren
    ~4,8 h gewesen. Da A-reconcile bereits nach 600 Laeufen mit 11,860 %
    Verlust dreimal schlechter ist als A, haetten weitere Laeufe die
    Entscheidung nicht veraendert. Sensitivitaetslaeufe: 1.000–2.000 Laeufe.
11. **Rollenwechsel des Primaergeraets nicht simuliert.** Variante B laeuft
    mit fest zugewiesenem Primaergeraet. Verlust des Primaergeraets,
    Rollenuebergabe und die dabei noetige Zustandsuebertragung sind
    ungetestet und die groesste offene Restunsicherheit von B.
12. **Determinismus des CBOR-Wire-Formats** (S7) ist Voraussetzung fuer
    stabile `msg_id`-Werte und wurde hier vorausgesetzt, nicht geprueft.

**Timebox:** Die Entscheidungslage ist eindeutig (0 vs. 415.090 Verluste bei
identischen Szenarien). Weitere Laeufe oder weitere Reconciliation-Varianten
haetten die Entscheidung nicht verbessert, deshalb Abbruch. Offen bleibt
Punkt 11 — der gehoert in die Umsetzung von Phase 2, nicht in diesen Spike.

---

## 11. Reproduktion

```
cd spikes/S2
cargo test --release                                        # 8 Kontrolltests

cargo run --release -- 10000 1 data/main_B.jsonl   30    0 B
cargo run --release -- 10000 1 data/main_A2.jsonl  30    0 A2
cargo run --release --  3500 1 data/main_A_1.jsonl 30    0 A
cargo run --release --  3500 1 data/main_A_2.jsonl 30 3500 A
cargo run --release --  3000 1 data/main_A_3.jsonl 30 7000 A
cargo run --release --   300 1 data/main_AR_1.jsonl 30   0 AR
cargo run --release --   300 1 data/main_AR_2.jsonl 30 300 AR

cargo run --release --  1000 1 data/sens_A_cap30.jsonl   30 0 A
cargo run --release --  1000 1 data/sens_A_cap200.jsonl 200 0 A
cargo run --release --  1000 3 data/sens_A_lat3.jsonl    30 0 A
cargo run --release --  2000 3 data/sens_B_lat3.jsonl    30 0 B
cargo run --release --  2000 3 data/sens_A2_lat3.jsonl   30 0 A2

cd analyze
cargo run --release -- ../data/main_A_1.jsonl ../data/main_A_2.jsonl \
  ../data/main_A_3.jsonl ../data/main_AR_1.jsonl ../data/main_AR_2.jsonl \
  ../data/main_B.jsonl ../data/main_A2.jsonl
```

Argumente: `<Laeufe> <Latenzmultiplikator> <Ausgabedatei> <max_attempts>
<Seed-Offset> <Variantenfilter>`.

Umgebung: Windows 11, x86_64-pc-windows-msvc, Rust 1.97.1 stable, 16 Threads.
Laufzeit der Hauptkampagne: 189 s (B) + 386 s (A2) + 661 s (A, 3 Teile) +
393 s (A-reconcile) = 1.629 s.
