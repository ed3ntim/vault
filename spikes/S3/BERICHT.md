# Spike S3 — Bericht: Revocation-Latenz (Descriptor-Republish)

**Spec:** `spec/phase0-spikeplan.md` §1 (S3), §3 (Kriterium/Fallback), §4, §6 ·
`spec/protokoll-spec.md` §11 · `spec/gesamtkonzept.md` §2.2 ·
ADR-15 (tragende Entscheidung) · ADR-16 (Umgebungslage)

**Gemessener Stand:** arti 0.44.0 (crates.io), Lauf 2026-07-25/26
**Umgebung:** Windows 11, x86_64-pc-windows-msvc, rustc 1.97.1 (8bab26f4f)
**Timebox:** abgebrochen, sobald weitere Arbeit die Entscheidungsgrundlage nicht
mehr verbessert hat (Begruendung in §5).

Zitat des Erfolgskriteriums (`spec/phase0-spikeplan.md` §3):

> **S3** | Revocation → Verbindungsverlust des Revozierten in < 5 min (p95);
> Intro-Point-Rotation greift | *Fallback:* Nutzer sichtbar warnen:
> „Trennung wird binnen X Minuten wirksam"

**Stand in einem Satz:** Der Prototyp der erzwungenen Rotation steht und ist
getestet, alle netzunabhaengigen Teilgroessen sind gemessen — die eigentliche
**Zeitmessung im laufenden Tor-Netz war nicht durchfuehrbar**, weil der
Arti-Bootstrap in dieser Umgebung erneut nicht abschliesst (wie in S1). Das
Kriterium ist damit **weder erfuellt noch widerlegt**; belegt ist dagegen, dass
es **ohne** die von ADR-15 geforderte erzwungene Rotation um Groessenordnungen
verfehlt wuerde.

---

## 1. Messergebnisse

### 1.1 Gegen das Erfolgskriterium selbst

| Teil des Kriteriums | Gemessen | Wert |
|---|---|---|
| Verbindungsverlust des Revozierten < 5 min (p95) | **nein — kein einziger Zeitwert** | — |
| „Intro-Point-Rotation greift" (im laufenden Netz) | **nein** | — |
| „Intro-Point-Rotation greift" (Descriptor-Ebene, offline) | **ja** | Schnittmenge der Intro-Point-Schluessel zwischen Epoche 0 und 1: **0 von 3** |

Es wird **keine** Latenzzahl gegen das 5-Minuten-Kriterium berichtet. Jede
solche Zahl waere erfunden. Was zur Messung fehlt, steht in §4.

### 1.2 Offline gemessen — Prototyp der erzwungenen Rotation

Programm `rot-proto/src/bin/rot_offline.rs`, Rohdaten
`ergebnisse/T-rot-offline.txt`. Descriptors werden ueber denselben
Bibliothekspfad gebaut, den `tor-hsservice` beim Publizieren nimmt
(`HsDescBuilder`, vgl. `tor-hsservice-0.44.0/src/publish/descriptor.rs`).
Kein Netzverkehr. Deterministischer RNG, Lauf reproduzierbar.

| # | Pruefung | Versuche | Ergebnis |
|---|---|---|---|
| R1 | Ausgangslage: 8 Kontakte, 3 Intro-Points, Descriptor 14.427 B | 8 | 8/8 Zugriff — PASS |
| R2 | Revozierter am **neuen** Descriptor (Epoche 1) | 500 | 500 abgewiesen, 0 durchgekommen = **100,0000 %** — PASS |
| R2 | verbliebene Kontakte am neuen Descriptor | 7 | 7/7 Zugriff — PASS |
| R3 | Intro-Point-Saetze Epoche 0 vs. 1 | — | Schnittmenge **0**, 3 alte abgerissen — PASS |
| R4 | Revozierter liest seinen **zwischengespeicherten** Descriptor der Epoche 0 nach der Revocation | 1 | **gelingt**, 3 Intro-Point-Schluessel weiterhin lesbar |
| R5 | `revision-counter` | — | 1 → 2, monoton — PASS |
| R7 | Leerfall: letzter Kontakt revoziert | 1 | Dienst wird vom Netz genommen statt mit 0 Clients publiziert — PASS |

**R4 ist der inhaltliche Kern des Spikes.** Der Descriptor-Republish entzieht
dem Revozierten nichts: er braucht den neuen Descriptor gar nicht, er hat den
alten. Wirksam wird die Revocation erst durch den **Abriss der alten
Introduction Points**. Genau das ist die Aussage von ADR-15, hier
reproduzierbar belegt.

### 1.3 Teilgroesse: lokaler Anteil einer Revocation

200 Laeufe je Reihenfolge, Nearest-Rank-Perzentile. Enthalten sind:
Credential-Entzug, `intro_point_epoch += 1`, Erzeugung frischer
Intro-Point-Schluessel, Descriptor bauen und signieren, Mesh-Entzug,
Session-Purge. **Nicht** enthalten: Circuit-Abriss, `ESTABLISH_INTRO`,
HSDir-Upload — also alle Netzanteile.

Werte des abgelegten Laufs (`ergebnisse/T-rot-offline.txt`):

| Reihenfolge | n | min | p50 | p95 | max |
|---|---|---|---|---|---|
| TeardownFirst | 200 | 0,652 ms | 0,663 ms | **0,855 ms** | 1,193 ms |
| MakeBeforeBreak | 200 | 0,652 ms | 0,663 ms | 0,731 ms | 1,192 ms |
| davon nur Descriptor bauen+signieren | 200 | 0,603 ms | 0,612 ms | 0,798 ms | 1,057 ms |

Wiederholmessung derselben Groessen in einem frueheren Lauf desselben Programms
(zur Streuung, nicht zur Auswahl): TeardownFirst p50 0,666 ms / p95 0,743 ms;
MakeBeforeBreak p50 0,668 ms / p95 1,033 ms; nur Descriptor p50 0,606 ms /
p95 0,683 ms. Der Unterschied zwischen beiden Reihenfolgen liegt innerhalb
dieser Streuung — **die Reihenfolge kostet lokal nichts**, ihr Unterschied
liegt vollstaendig im Netzanteil.

Skalierung ueber die Zahl verbleibender Kontakte (20 Laeufe je Punkt):

| verbleibende Kontakte | p50 | p95 | Descriptor |
|---|---|---|---|
| 1 | 0,440 ms | 0,515 ms | 14.427 B |
| 5 | 0,622 ms | 0,754 ms | 14.427 B |
| 10 | 0,808 ms | 0,945 ms | 14.427 B |
| 20 | 1,189 ms | 1,280 ms | 14.427 B |
| 40 | 1,963 ms | 2,288 ms | 14.427 B |
| 80 | 3,527 ms | 3,675 ms | 14.427 B |

**Einordnung:** Der lokale Anteil betraegt bei der in ADR-16 vorlaeufig
genannten Obergrenze von 80 Kontakten je Kompartiment **unter 4 ms** — das sind
**0,0013 %** des 300-Sekunden-Budgets. Die Latenz entsteht vollstaendig im Netz.
Das ist eine Teilgroesse, **keine** Erfuellung des Kriteriums.

### 1.4 Gemessen: welche Hebel arti 0.44.0 fuer die Rotation bietet

Gemessen per Compilerlauf (`bash spikes/S3/pruefe-rotations-api.sh`), Rohdaten
`ergebnisse/T-rotations-api.txt`. Alle Negativbefunde sind `error[E0599]`
(„no method named …"), also Abwesenheit der Methode und nicht ein Fehler des
Testaufbaus. Ohne Feature `experimental-api`.

| Hebel | vorhanden | Belegstelle / Fehler |
|---|---|---|
| L1 `RunningOnionService::reconfigure` (Clientliste verkleinern) | **ja** | uebersetzt (64 s) |
| L2 `pause()` (Dienst anhalten) | **nein** | `E0599: no method named 'pause'`; im Quelltext auskommentiert, `lib.rs:552-561`, TODO #1231 |
| L3 `rotate_intro_points()` | **nein** | `E0599: no method named 'rotate_intro_points'` |
| L4 letzten `Arc` fallen lassen + `launch_onion_service` | **ja** | uebersetzt |
| C1 Rotation aus `OnionServiceStatus` bestaetigbar | **nein** | `E0599` fuer `published_revision_counter` **und** `intro_points` |

**Folge fuer ADR-15:** Die geforderte erzwungene Rotation ist mit der
oeffentlichen API **nur ueber L4** erreichbar — den Dienst beenden und neu
starten. Und **C1 fehlt**: ADR-15 Punkt 3 („eine Revocation gilt erst als
wirksam, wenn die Rotation bestaetigt ist") laesst sich mit der Status-API
**nicht praezise** umsetzen; sie liefert nur `Shutdown / Bootstrapping /
Running / Degraded… / Recovering / Broken`, weder Revisionsnummer noch
Intro-Point-Liste.

### 1.5 Gemessen: L4 allein rotiert nicht

Aus dem Quelltext der installierten Crate-Version, reproduzierbar mit
`bash spikes/S3/pruefe-arti-konstanten.sh`, Rohdaten
`ergebnisse/T-arti-konstanten.txt`:

`tor-hsservice-0.44.0/src/ipt_mgr/persist.rs:143-182` stellt beim Neustart
**dieselben** Intro-Point-Relays wieder her — mit denselben Schluesseln
(`Some(IptExpectExistingKeys)`, Zeile 159) — und ruft sofort
`start_accepting` (Zeile 182).

**Ein blosser Neustart des Dienstes rotiert die Introduction Points also
nicht.** Vault muss zusaetzlich den persistenten IPT-Zustand und die
IPT-Schluessel loeschen. Der Prototyp `s3-live` tut das
(`purge_intro_point_state`), **aber ueber Pfadannahmen und nicht ueber eine
API** — und dieser Pfad konnte hier nicht gegen einen laufenden Dienst
verifiziert werden (§4).

### 1.6 Abgeleitet, nicht gemessen: was ohne erzwungene Rotation passiert

Reine Arithmetik aus den Konstanten in §1.5 / `ergebnisse/T-arti-konstanten.txt`.
**Keine Messwerte** — aber aus dem Quelltext der eingesetzten Version.

| Groesse | Wert | Quelle |
|---|---|---|
| Lebensdauer des publizierten Descriptors | **3 h** | `ipt_mgr.rs:27,29` (`IPT_PUBLISH_UNCERTAIN` = `IPT_PUBLISH_CERTAIN`) |
| geplante Rotation eines Intro-Point-Relays | **zufaellig 18–24 h** | `ipt_mgr.rs:1627-1641`, Konsensparameter `hs_intro_min/max_lifetime`, Vorgaben `tor-netdir-0.44.0/src/params.rs:537,541` |
| Nachhalten eines alten Intro-Points nach Descriptor-Ablauf | **+15 min** (10 min + `OVERALL_UPLOAD_TIMEOUT`) | `ipt_set.rs:136-137` |
| Zeitbudget eines Descriptor-Uploads | **5 min** | `publish/reactor.rs:130` |
| Mindestabstand zweier Uploads | **60 s** | `publish/reactor.rs:113` |
| Schwelle, ab der ein Intro-Point als fehlerhaft gilt | **15 min** | `ipt_establish.rs:502` |

Daraus folgt fuer die Variante „nur Clientliste verkleinern" (Hebel L1): Der
Introduction Point, den der Revozierte kennt, bleibt **18 bis 24 Stunden**
registriert, danach noch bis zu **3 h 15 min** nachgehalten. Untere Schranke
**18 h = 64.800 s**, das ist das **216-fache** des 300-Sekunden-Kriteriums;
obere Schranke rund **27 h**.

Zusaetzlich, aus der Modul-Doku derselben Datei
(`config/restricted_discovery.rs:48-62`, vollstaendiges Zitat in
`ergebnisse/T-arti-konstanten.txt` Abschnitt 8) — der Teil, den ADR-15 noch
nicht zitiert:

> „Moreover, even if the introduction points are rotated by chance, your
> changes are not guaranteed to take effect immediately, so it is possible for
> the service to publish its new introduction points in a descriptor that is
> **readable by the recently unauthorized client**."

Das ist schaerfer als bisher angenommen: Ohne Kontrolle ueber die Reihenfolge
kann der Republish dem gerade Revozierten die **neuen** Intro-Points
aushaendigen. Da C1 fehlt (§1.4), kann Vault ueber die oeffentliche API nicht
pruefen, ob das passiert ist.

Und `lib.rs:495-497` (im `reconfigure`-Rumpf):

> „TODO (#1153, #1209): We need to make sure that the various tasks listening
> on `config_rx` actually enforce the configuration, not only on new
> connections, but **existing ones**."

### 1.7 Tests des Prototyps

`cd spikes/S3/rot-proto && cargo test --release`, Rohdaten
`ergebnisse/T-rot-proto-tests.txt`:

| Testebene | Anzahl | Ergebnis |
|---|---|---|
| Unit (`stats`) | 3 | 3 bestanden |
| Integration (`tests/rotation.rs`) | 13 | 13 bestanden |
| **Summe** | **16** | **16 bestanden, 0 fehlgeschlagen** |

Abgedeckt sind die Schritte 1–5 aus `spec/protokoll-spec.md` §11 einzeln, die
Disjunktheit der Intro-Point-Saetze, die Lesbarkeit des alten Descriptors durch
den Revozierten, der Leerfall nach ADR-16 Punkt 6, beide Rotationsreihenfolgen
und die Auswertung gegen die 300-Sekunden-Schwelle. Die Zeitmodell-Tests
arbeiten mit **synthetischen** Verzoegerungen; sie pruefen die Rechenlogik, sie
sind ausdruecklich keine Messwerte und sind im Quelltext so gekennzeichnet.

Schritt 6 aus §11 (`replicate RevocationNotice an eigene Geraete`) ist **nicht**
modelliert — er liegt auf dem Netzpfad und haengt am Primaergeraet-Modell
(ADR-17).

### 1.8 Die Ende-zu-Ende-Versuche

Programm `s3-live` gebaut mit `cargo build --release`: erfolgreich,
**2 min 44 s**, 501 Pakete. Rohdaten `ergebnisse/T-live-versuch.txt`.

| Versuch | Start (UTC) | Bootstrap-Timeout | Ergebnis |
|---|---|---|---|
| 1 | 22:23:57 | 420 s | Ausgabe endet nach `1: Looking for a consensus. attempt=1`; Prozess nach rund 10 min extern beendet |
| 2 | 22:36:32 | 240 s | zusaetzlich `Another process is bootstrapping the directory` (Sperre aus Versuch 1); Abbruch nach 240 s, Exitcode 1 |
| 3 | 22:41:17 | 300 s, **frisches** Arbeitsverzeichnis | erneut Stillstand bei `Looking for a consensus`; Prozess terminierte **nicht** zu seinem eigenen Timeout, nach rund 14 min extern beendet |

**In keinem Versuch wurde ein Onion-Service erreicht. Es gibt keine
Latenzmesswerte.** Der Befund deckt sich mit S1
(`spikes/S1/ergebnisse/T-arti-bootstrap-versuch.txt`: zwei Laeufe ueber 15 bzw.
8 min ohne Bootstrap).

Ein Nebenbefund aus Versuch 3 betrifft das Messrig selbst und wurde behoben:
Der Abbruchpfad terminierte nicht, weil das Fallenlassen eines halb gebooteten
`TorClient` haengt. Das Programm bricht jetzt hart ab. Kontrolllauf
(`ergebnisse/T-live-abbruchpfad.txt`, Bootstrap-Timeout absichtlich 45 s):
Abbruch nach **45 s** mit Exitcode 3, sauber beendet. Das ist **kein**
Latenzmesswert, sondern der Nachweis, dass das Rig bedienbar ist.

Danach wurde nicht weiter am Bootstrap gearbeitet: ein vierter Beleg fuer
dasselbe Umgebungsproblem verbessert die Entscheidungsgrundlage nicht.

---

## 2. Zeitbudget: was bekannt ist und was fehlt

Zerlegung des Wegs vom Revocation-Ausloeser bis zum belegten
Verbindungsverlust des Revozierten, fuer die **erzwungene** Rotation (L4 +
Purge):

| Term | Groesse | Status |
|---|---|---|
| Schritt 1–2 (§11): Credential-Entzug, `epoch += 1` | Teil der 0,855 ms (p95) | **gemessen** |
| Erzeugung frischer Intro-Point-Schluessel | Teil der 0,855 ms (p95) | **gemessen** |
| Descriptor bauen und signieren | p95 0,798 ms | **gemessen** |
| Beenden des Dienstes, Loeschen des IPT-Zustands | Dateisystem | **nicht gemessen** (Pfad nie gegen laufenden Dienst ausgefuehrt) |
| **Abriss der alten Intro-Point-Circuits (DESTROY)** — *hier verliert der Revozierte den Zugang* | Netz-RTT | **nicht gemessen** |
| Aufbau von 3 neuen Intro-Points (`ESTABLISH_INTRO`) | — | **nicht gemessen**; Bibliotheks-Obergrenze fuer den anschliessenden Upload: 5 min |
| Descriptor-Upload an die HSDirs | — | **nicht gemessen**; Bibliotheksbudget 5 min, Mindestabstand 60 s |
| Bestaetigung der Rotation (ADR-15 Punkt 3) | — | **nicht beobachtbar** (C1 fehlt) |

Der einzige Term, der ueber Erfolg oder Misserfolg des Kriteriums entscheidet,
ist der Circuit-Abriss — und genau er ist hier nicht messbar.

---

## 3. Empfehlung

**Ergebnis: blockiert — Mess-Kit steht, Messung fehlt.**
Nicht „bestanden", nicht „gescheitert".

Begruendung:

1. **Kein Zeitwert gegen das Kriterium.** Ohne Tor-Netz kein Verbindungsverlust,
   ohne Verbindungsverlust keine Latenz. Der Spike kann die Entscheidung, fuer
   die er gedacht ist, nicht treffen.
2. **Der Fallback aus der Spec ist derzeit nicht ausfuellbar.** Er lautet
   „Nutzer sichtbar warnen: ‚Trennung wird binnen X Minuten wirksam'". **X ist
   nicht bestimmbar**, weil keine Messung vorliegt. Der Fallback kann deshalb
   nicht gezogen, sondern nur vorgemerkt werden. Ihn mit einem geschaetzten X
   zu belegen waere dieselbe Klasse von Unehrlichkeit wie ein `delivered` ohne
   E2E-ACK.
3. **ADR-15 wird durch die Befunde gestuetzt, nicht in Frage gestellt.**
   R4 zeigt offline, dass der Republish allein nichts entzieht; §1.6 leitet aus
   dem Quelltext her, dass der Zugang ohne erzwungene Rotation **18 bis 27
   Stunden** bestehen bleiben kann statt < 5 min. Die Entscheidung, die Rotation
   selbst zu erzwingen, ist damit nicht nur plausibel, sondern notwendig.
4. **Neu gegenueber ADR-15:** Die erzwungene Rotation ist mit der
   oeffentlichen API von arti 0.44.0 nur ueber „Dienst beenden und neu starten"
   erreichbar (L2/L3 existieren nicht), sie erfordert zusaetzlich das Loeschen
   des persistenten IPT-Zustands (sonst kehren dieselben Intro-Points zurueck),
   und ihre **Bestaetigung** ist ueber die Status-API nicht ablesbar. Punkt 3
   von ADR-15 ist damit heute nicht sauber implementierbar.
5. **A4 im Threat Model bleibt ◐.** ADR-15 Punkt 5 macht ○ vom Nachweis durch
   S3 abhaengig. Der Nachweis liegt nicht vor.

**Was das fuer den Spike-Status heisst:** S3 ist offen und muss auf einem Host
mit funktionierendem Tor-Zugang nachgezogen werden. Die dafuer noetige Arbeit
ist getan; es fehlt ausschliesslich die Umgebung (§4, §6).

---

## 4. Was nicht geprueft werden konnte — und warum

| # | Nicht geprueft | Grund | Was noetig waere |
|---|---|---|---|
| 1 | Die Latenz selbst (Kriterium) | Arti-Bootstrap schliesst hier nicht ab: `Looking for a consensus` ohne Fortschritt in drei Versuchen (§1.8); identischer Befund wie S1 | Host mit ungefiltertem Tor-Zugang, dann `bash spikes/S3/live-versuch.sh ab 1800 15 600` |
| 2 | Ob der Abriss alter Intro-Points den Revozierten tatsaechlich sofort aussperrt | erfordert laufende Intro-Point-Circuits | wie #1 |
| 3 | Ob `purge_intro_point_state` die richtigen Pfade trifft | nie gegen einen laufenden Dienst ausgefuehrt; die Pfade sind **Annahmen** ueber Artis Zustandsverzeichnis, keine API | wie #1; die Funktion meldet beim ersten echten Lauf, was sie geloescht hat |
| 4 | Erreichbarkeitsluecke fuer die verbliebenen Kontakte (Preis der Rotation) | Netzgroesse | wie #1; das Messrig erhebt sie als `t_wiederkehr` |
| 5 | Verhalten eines **feindlichen** Revozierten | Das Rig misst mit einem unveraenderten Arti-Client. Der respektiert `descriptor-lifetime` und holt den Descriptor neu; ein feindlicher Client wuerde stattdessen seine zwischengespeicherten Intro-Points weiter benutzen. **Variante A wuerde damit zu optimistisch messen.** Variante B ist davon nicht betroffen, weil dort die Circuits abgerissen sind | Ein Messclient, der Intro-Points aus dem Cache weiterbenutzt und den Descriptor nicht neu holt — vermutlich ein gepatchter `tor-hsclient` |
| 6 | Ob der Republish dem gerade Revozierten die **neuen** Intro-Points aushaendigen kann (Doku-Zitat §1.6) | erfordert einen eigenen HSDir-Beobachter im laufenden Netz | privates Tor-Testnetz (chutney) — dieselbe offene Auflage wie in S1/ADR-16 Folgearbeit 2 |
| 7 | Schritt 6 aus §11 (Replikation der `RevocationNotice` an eigene Geraete) | Netzpfad, haengt an ADR-17 | zusammen mit dem Multi-Device-Pfad |
| 8 | Mesh-Anteil der Revocation (§11 Schritt 4, `mesh_visibility`) | kein Mesh-Stack vorhanden | eigener Spike |
| 9 | Verhalten auf Android / Linux / iOS | keine Hosts (identisch zu S1/ADR-16) | siehe ADR-16 Folgearbeit 1 |
| 10 | C-tor als Alternative | kein `tor`-Binary; GATE-1 offen | siehe ADR-16 |

---

## 5. Abbruchbegruendung (Timebox)

Die Spec setzt fuer S3 3 Tage. Abgebrochen wurde nach:

- Prototyp + Tests + Offline-Messung fertig und gruen,
- API-Hebel per Compiler geklaert (5 Probe-Laeufe),
- zeitbestimmende Konstanten aus dem Quelltext belegt,
- Ende-zu-Ende-Rig gebaut, dreimal gestartet, Abbruchpfad repariert und
  kontrolliert.

Der einzige verbleibende Schritt waere ein weiterer Bootstrap-Versuch gewesen.
S1 hat denselben Versuch bereits zweimal ueber 15 bzw. 8 Minuten ohne Erfolg
unternommen, S3 dreimal; ein sechster Beleg haette die Entscheidungsgrundlage
nicht verbessert. Deshalb Abbruch mit Bericht statt weiterer Versuche.

---

## 6. Offene Fragen an den Menschen

Keine davon ist von mir entschieden worden.

1. **Rotationsreihenfolge.** `spec/protokoll-spec.md` §11 Schritt 3 legt nicht
   fest, ob erst abgerissen und dann neu aufgebaut wird (`TeardownFirst`:
   Revozierter sofort draussen, eigener Dienst kurzzeitig fuer **alle** offline)
   oder umgekehrt (`MakeBeforeBreak`: keine Luecke, Revozierter behaelt bis zum
   Abriss einen Pfad). Der Prototyp kann beides. Der Prioritaetsstack legt
   `TeardownFirst` nahe (Prioritaet 1 vor Prioritaet 3), das ist aber eine
   Designentscheidung und gehoert in die Spec, nicht in Spike-Code.
2. **Wie wird „bestaetigte Rotation" (ADR-15 Punkt 3) operationalisiert,** wenn
   die Status-API weder Revisionszaehler noch Intro-Point-Liste hergibt (C1,
   §1.4)? Ein moeglicher Ersatz waere der beobachtbare Uebergang
   `Shutdown → Bootstrapping → Running` nach dem erzwungenen Neustart. Der
   belegt aber nur, dass der Dienst wieder laeuft — **nicht**, dass die alten
   Intro-Points tot sind. Reicht das als Grundlage fuer die Anzeige „getrennt"?
3. **Darf Vault sich auf Dateipfade in Artis Zustandsverzeichnis stuetzen,**
   um den IPT-Zustand zu loeschen (§1.5)? Das ist keine API und bricht bei
   jedem Upgrade still. Alternativen: Upstream-Anfrage nach einem
   `rotate_intro_points()`, eigener Fork, oder Kapselung mit Vertragstests
   entlang Auflage A2 aus S1 / ADR-16 Punkt 5.
4. **Welcher Text bei welchem X im Fallback?** Der Spec-Fallback verspricht
   „binnen X Minuten". Ohne Messung gibt es kein X. Falls die Nachmessung das
   Kriterium reisst, waere „Minuten" moeglicherweise die falsche Einheit —
   ohne erzwungene Rotation waeren es abgeleitet 18–27 **Stunden**. Die
   UI-Sprache muss zum tatsaechlichen Wert passen.
5. **Soll §11 um den Purge-Schritt und die Reihenfolge ergaenzt werden?** Der
   heutige Text („`tor: rotate_intro_points(onion_c)`") beschreibt einen
   Aufruf, den es in der Zielbibliothek nicht gibt. Eine Spec-Aenderung habe
   ich ausdruecklich nicht vorgenommen.
6. **Notfallweg.** ADR-15 nennt „Kompartiment komplett neu aufsetzen" als
   verworfene Regelloesung, die als Notfallweg bleibt. Falls die Nachmessung
   zeigt, dass die erzwungene Rotation das Kriterium nicht haelt, ist das die
   einzige belegbar wirksame Option — zum Preis der Neu-Verifikation aller
   Kontakte, den §2.2 ausschliesst. Diese Abwaegung braucht eine Entscheidung,
   bevor gemessen wird, damit die Messung sie nicht praejudiziert.
7. **Messmethodik fuer den feindlichen Fall** (§4 Punkt 5): Soll fuer die
   Nachmessung ein gepatchter Client gebaut werden, der zwischengespeicherte
   Intro-Points weiterbenutzt? Ohne ihn misst Variante A einen
   kooperativen Client und damit zu guenstig.

---

## 7. Risikoregister-Rueckmeldung

`spec/phase0-spikeplan.md` §6: Fuer S3 existiert **keine** eigene Risikozeile.
R-1 („Arti-Client-Auth nicht produktionsreif") deckt den Befund nur teilweise
ab, denn das Problem liegt nicht in der Client-Auth, sondern in der fehlenden
Steuerbarkeit der Introduction Points.

**Vorschlag** (keine Aenderung von mir vorgenommen): eine Zeile aufnehmen —
„Revocation-Wirksamkeit nicht nachweisbar / Latenz ueber Budget", W mittel,
A **sehr hoch** (`spec/gesamtkonzept.md` §2.2 und `spec/threat-model.md` §4/A4
haengen direkt daran), Massnahme: erzwungene Rotation nach ADR-15 plus
Nachmessung auf einem Host mit Tor-Zugang; Fruehindikator: dieser Bericht.

---

## 8. Verzeichnis der Artefakte

| Pfad | Inhalt |
|---|---|
| `rot-proto/src/lib.rs` | Zustandsmaschine nach §11, Transport-Schnittstelle, Zeitachse |
| `rot-proto/src/desc.rs` | Descriptor-Bau und -Zugriff ueber `tor-netdoc`, `LocalTransport` |
| `rot-proto/src/stats.rs` | Perzentile und Urteil gegen die 300-Sekunden-Schwelle |
| `rot-proto/src/bin/rot_offline.rs` | Messprogramm R1–R8 |
| `rot-proto/tests/rotation.rs` | 13 Integrationstests |
| `rotations-api/src/lib.rs` | Compilerprobe der Rotations-Hebel L1–L4, C1 |
| `s3-live/src/bin/revocation_latency.rs` | Ende-zu-Ende-Messrig, Varianten A und B |
| `pruefe-rotations-api.sh` | reproduziert §1.4 |
| `pruefe-arti-konstanten.sh` | reproduziert §1.5 und §1.6 |
| `live-versuch.sh` | fuehrt das Messrig aus |
| `ergebnisse/T-rot-offline.txt` | Rohausgabe R1–R8 |
| `ergebnisse/T-rot-proto-tests.txt` | Rohausgabe der Testlaeufe |
| `ergebnisse/T-rotations-api.txt` | Rohausgabe der Compilerproben inkl. Fehlercodes |
| `ergebnisse/T-arti-konstanten.txt` | Quelltextbelege der Konstanten |
| `ergebnisse/T-live-versuch.txt` | Protokoll der drei Ende-zu-Ende-Versuche |
| `ergebnisse/T-live-abbruchpfad.txt` | Kontrolllauf des Abbruchpfads (kein Messwert) |
