# ADR-15: Multi-Device-Architektur — Primaergeraet mit Read-Through-Replikaten

> **ENTWURF aus Spike S2.** Noch nicht nach `adr/` uebernommen. Die endgueltige
> Nummer vergibt die Projektleitung fortlaufend (`adr/README.md`).

- **Status:** vorgeschlagen
- **Datum:** 2026-07-25
- **Betrifft:** `spec/protokoll-spec.md` §2 (Schluesselhierarchie), §8, §9.1–9.4, §10;
  `spec/gesamtkonzept.md` §2.6; Crates `vault-delivery`, `vault-crypto`,
  `vault-core`, `vault-storage`
- **Loest Gate:** GATE-2

## Kontext

`spec/phase0-spikeplan.md` §2 (S2) stellt die Frage woertlich:

> „Funktioniert paarweiser Double-Ratchet-Sync zwischen eigenen Geraeten
> robust, oder braucht es ein Primaergeraet-Modell?"

und begruendet die Kritikalitaet:

> „Seit Wegfall der Mailbox traegt Multi-Device die asynchrone Zustellung.
> Fehler fuehren zu **Nachrichtenverlust oder Doppelentschluesselung** — die
> schlimmste Fehlerklasse."

Der zu pruefende Entwurf steht in `spec/protokoll-spec.md` §9.3:

> „Eigene Geraete bilden ein **voll vernetztes Intra-Identity-Mesh** mit
> paarweisen DR-Sitzungen (Geraeteschluessel-basiert). Darueber laufen
> `SyncRecord` (Verlauf, Ratchet-Fortschritt, Kontaktliste,
> Kompartiment-Keys). […] **Konfliktfall** (zwei Geraete empfangen
> gleichzeitig auf derselben Kontakt-Session, bevor sie syncen): toleriert
> durch DR-Skipped-Message-Keys; anschliessende Reconciliation waehlt den vom
> Sender zuerst quittierten Zweig, das andere Geraet holt per `SyncRecord`
> nach."

Derselbe Abschnitt benennt den Fallback:

> „Fallback-Option, falls paarweiser DR-Sync zu teuer: ein designiertes
> Primaergeraet haelt den kanonischen Session-Zustand, Zweitgeraete sind
> Read-Through-Replikate mit Send-Proxy uebers Primaergeraet."

`spec/protokoll-spec.md` §2 legt fest, dass es **eine** Session je Kontakt
gibt („Pro Sitzung mit X: Double-Ratchet-Zustand DR_X"), nicht eine je
Geraetepaar.

**Datengrundlage:** Spike S2, `spikes/S2/BERICHT.md`. Simulation mit echten
Primitiven (X25519, HKDF-SHA-256, HMAC-SHA-256, XChaCha20-Poly1305, BLAKE3)
und vendorter Double-Ratchet-Implementierung; 10.000 randomisierte Laeufe je
Variante zu je 1.000 Nachrichten, 2–3 eigene Geraete, vier Szenarioprofile.

## Entscheidung

**Vault setzt fuer Multi-Device das Primaergeraet-Modell um (Variante B).**

1. Je Kontakt existiert genau **ein** Double-Ratchet-Zustand. Er liegt
   ausschliesslich auf dem **Primaergeraet** des Kompartiments. Kein anderes
   Geraet haelt `RK`, `CKs`, `CKr` oder private Ratchet-Schluessel dieser
   Session.
2. Zweitgeraete sind **Read-Through-Replikate**: sie erhalten Klartext-Verlauf
   und Metadaten ueber das paarweise Geschwister-Mesh (dieses bleibt
   unveraendert bestehen und nutzt weiterhin Double Ratchet je Geraetepaar).
3. Die Geraeteliste (§9.1) enthaelt weiterhin **alle** Geraete. Ein
   Zweitgeraet nimmt Envelopes an und leitet sie als **opake Bytes** an das
   Primaergeraet weiter (Store-and-Forward). Es kann sie nicht entschluesseln.
4. **`delivered` setzt ausschliesslich das Primaergeraet**, nachdem es
   entschluesselt hat und sein Ack beim Kontakt angekommen ist (§9.4,
   `CLAUDE.md`). Ein Zweitgeraet quittiert nie. Bis dahin zeigt die
   Gegenseite `WAITING`.
5. Senden vom Zweitgeraet laeuft als **Send-Proxy** ueber das Primaergeraet.
   Ist das Primaergeraet unerreichbar, ist das Zweitgeraet in dieser Session
   **nicht sendefaehig**; die UI sagt das ausdruecklich.
6. Die Primaerrolle ist **je Kompartiment** zugewiesen, nutzerseitig
   umsetzbar und wird per signiertem `DeviceListUpdate` propagiert. Ein
   Rollenwechsel uebertraegt den Sitzungszustand ueber das Geschwister-Mesh
   und ist gegenueber dem Kontakt ein gewoehnlicher DH-Ratchet-Schritt.
7. Der Empfaenger fuehrt je Session einen Cache `H(Envelope) → msg_id` und
   beantwortet einen erneut zugestellten Envelope mit einem **frisch
   verschluesselten** Ack, ohne erneute Entschluesselung. Ohne diese Regel ist
   das Zustellmodell nicht abschliessbar (Befund F-3 im Spike-Bericht); sie
   ist in `spec/protokoll-spec.md` §9.2/§9.3 nachzutragen.

`spec/protokoll-spec.md` §9.3 ist entsprechend zu aendern: der dort
beschriebene geteilte Kontakt-Session-Zustand mit `dr_delta`-Replikation
entfaellt. `SyncRecord` transportiert Klartext-Verlauf, Kontaktliste,
Kompartiment-Credentials und Revocation-Nachrichten — **keinen**
Kontakt-Ratchet-Zustand.

## Alternativen

### A — Geteilte Kontakt-Session mit `dr_delta`-Replikation (§9.3 im Wortlaut)

Verworfen. Der Double Ratchet ist ein Zwei-Parteien-Protokoll; sein
**Sendezustand** ist ohne Serialisierung nicht replizierbar. §9.3 verlangt
zugleich, dass **jedes** empfangende Geraet quittiert („persist(pt); send
Ack") — damit senden zwangslaeufig mehrere Geraete auf derselben Session.
Folgen, im Spike gemessen und im Kontrolltest isoliert nachgewiesen:

- Zwei Geraete belegen dieselbe Kettenposition `(dh_pub, n)`. Der Kontakt
  kann genau einen der beiden Envelopes lesen; der zweite ist dauerhaft
  unlesbar, weil der Message Key nach Gebrauch geloescht wird — genau die
  Forward-Secrecy-Eigenschaft, die gewollt ist.
- Zieht ein Geraet seinen DH-Ratchet-Schluessel aus echter Entropie, bevor
  ein `dr_delta` mit dem privaten Ratchet-Schluessel eingetroffen ist,
  divergiert der Wurzelschluessel dauerhaft. Das Geraet kann die Session
  danach nicht mehr benutzen.
- Damit Variante A ueberhaupt funktionieren koennte, muessten **private
  Ratchet-Schluessel** zwischen Geraeten repliziert werden. Das hebt die
  Post-Compromise-Security fuer die gesamte Geraetemenge auf.

Die Messwerte stehen im Spike-Bericht; Variante A verfehlt das Kriterium
„0 Nachrichtenverluste" deutlich.

### A-reconcile — Variante A mit Zustandssnapshot vom kanonischen Geraet

Verworfen. Die in §9.3 skizzierte Reconciliation („waehlt den vom Sender
zuerst quittierten Zweig") wurde als Uebernahme eines vollstaendigen
Zustandssnapshots vom Geraet mit der niedrigsten ID umgesetzt, ohne
Rueckschritt der Empfangskette. Ergebnis: **schlechter** als A. Ursache:
DH-Ratchet-Schritte sind nicht kommutativ; ein Snapshot ist beim Eintreffen
bereits veraltet, und die uebernehmende Seite verliert eigenen
Empfangsfortschritt. Jede korrekte Reconciliation muss die Sendevorgaenge
serialisieren — womit sie zu Variante B wird.

### A2 — Eine Kontakt-Session je eigenem Geraet

Nicht Teil des Spike-Auftrags, aber mitgemessen, weil es die dritte
naheliegende Loesung ist (Signal-Ansatz: Session je `(Identitaet, Geraet)`).
Ergebnis: 0 Nachrichtenverluste, 0 Konvergenzluecken — aber **echte
Duplikate**, weil `msg_id = H(dr_header ‖ ciphertext)` (§8) nicht stabil ist,
sobald dieselbe Nachricht fuer ein anderes Zielgeraet neu verschluesselt wird.
Weitere Kosten: N Prekey-Handshakes je Kontakt, und der Sender muss den
**Klartext** in der Ausgangswarteschlange halten, bis das Zielgeraet
feststeht — das kollidiert mit ADR-13 (selbstloeschende Nachrichten als
Default) und mit `gesamtkonzept.md` §2.6 Punkt 1 („Die **verschluesselte**
Nachricht bleibt beim Sender").

A2 ist mit einer stabilen, senderseitig vergebenen Nachrichten-ID reparierbar
und bleibt damit ein moeglicher spaeterer Migrationspfad. Das erfordert eine
Aenderung an §8 und einen eigenen ADR und wird hier **nicht** entschieden.

### Verworfene Ansaetze aus Anhang A

Nicht erneut aufgerollt. Insbesondere loest dieser ADR das Zustellproblem
**nicht** durch Mailbox, Relay oder Zwischenspeicher.

## Auswirkung auf das Threat Model

**Pflichtfeld.**

| Angreifer / Asset | Wirkung | Bewertung |
|---|---|---|
| **A4 (uebernommener Kontakt) / G3 (Praesenzmuster)** | `spec/threat-model.md` mindert Praesenz-Probing durch einen autorisierten Kontakt mit „Multi-Device: nur ‚mindestens ein Geraet erreichbar'". Diese Minderung **schwaecht sich ab**: Ein E2E-Ack kommt nur, wenn das **Primaergeraet** erreichbar ist. Der Kontakt kann daraus ein feineres Praesenzsignal ableiten (Praesenz *eines bestimmten* Geraets statt „irgendeines"). | **Verschlechterung.** Gegenmassnahme: Zweitgeraete nehmen Envelopes weiterhin an und leiten sie weiter — der Verbindungsaufbau bleibt also ununterscheidbar; nur das Ack-**Timing** traegt Information. Diese ist durch das einheitliche Netzprofil zu daempfen (Ack-Zeitpunkt an Sync-Fenster/Jitter binden, GATE-3). Restrisiko bleibt **◐** und ist zu dokumentieren. |
| **A7 (aktiver Netzangreifer) / G8 (Zustellbarkeit)** | Die Zustellung haengt jetzt an der Erreichbarkeit eines bestimmten Geraets. Gezielte Verfuegbarkeitsangriffe gegen das Primaergeraet verzoegern die Zustellung. | **Verschlechterung der Latenz, nicht der Korrektheit.** Der Status bleibt ehrlich (`WAITING`, nie „zugestellt"). Zweitgeraete puffern die Envelopes weiterhin, so dass nichts verloren geht. Gegenueber Variante A ist das eine **Verbesserung**, denn dort entstand echter Nachrichtenverlust — die Threat-Model-Zeile „G8: gezielte Nichtzustellung / stiller Drop → ○" ist mit Variante A nicht haltbar. |
| **A8 / SA-6 (Geraetekompromittierung, out of scope)** | Variante A haette private Ratchet-Schluessel und Chain Keys ueber alle eigenen Geraete verteilt. B haelt den Sitzungszustand auf genau einem Geraet. | **Verbesserung.** Die Angriffsflaeche fuer Sitzungsschluessel sinkt von N Geraeten auf 1. Post-Compromise-Security des Double Ratchet bleibt wirksam; unter A waere sie fuer die gesamte Geraetemenge aufgehoben gewesen. |
| **A1/A2 (Netzbeobachter) / G5** | Keine Aenderung am Netzprofil, keine neuen Verbindungsmuster, keine neuen Identifier. | **Neutral.** |
| **A3 (Tor-Infrastruktur) / G2** | Keine zusaetzlichen Onion-Services, keine Aenderung am Descriptor-Volumen. | **Neutral.** |
| **Neues Restrisiko** | **R-11: Primaergeraet als Verfuegbarkeits- und Praesenz-Einzelpunkt.** Kein Vertrauens-Einzelpunkt (das Geraet gehoert dem Nutzer), aber ein Verfuegbarkeitsengpass und ein feineres Praesenzsignal. Minderung: Store-and-Forward auf Zweitgeraeten, nutzerseitiger Rollenwechsel, Ack-Timing im einheitlichen Netzprofil. | aufzunehmen in `spec/threat-model.md` §6 |

**Anonymitaetsset (`gesamtkonzept.md` §2.9):** unveraendert. Die Entscheidung
fuehrt keine Option und keine Konfigurierbarkeit ein; alle Installationen
verhalten sich gleich. Die Primaerrolle ist eine lokale Zuordnung ohne
Aussenwirkung auf das Netzprofil.

## Auswirkung auf den Prioritaetsstack

- **Prioritaet 1 (Anonymitaet/Datenschutz):** beruehrt, aber nicht verletzt.
  Das feinere Praesenzsignal gegenueber einem autorisierten Kontakt (A4/G3)
  ist die einzige Verschlechterung; sie betrifft nur bereits autorisierte
  Kontakte, nicht Dritte, und wird durch Store-and-Forward plus Ack-Jitter
  gedaempft. Demgegenueber verbessert die Entscheidung den Schutz von
  Sitzungsschluesseln deutlich. Netto vertretbar.
- **Prioritaet 2 (Serverlosigkeit):** nicht beruehrt. Das Primaergeraet ist
  ein Geraet des Nutzers, kein Dritter, kein Betreiber, kein Verzeichnis. Es
  entsteht keine Infrastruktur.
- **Prioritaet 3 (Komfort):** wird geopfert — genau wie vom Prioritaetsstack
  vorgesehen. Ein Zweitgeraet ohne erreichbares Primaergeraet ist nicht
  sendefaehig, und die Zustellung kann laenger `WAITING` bleiben.

## Konsequenzen

**Leichter:**

- `vault-delivery` braucht keine Konfliktaufloesung fuer Kontakt-Sessions.
  Der komplexeste Teil des Entwurfs entfaellt ersatzlos.
- Der Sitzungszustand hat genau einen Schreiber. Das macht ihn testbar,
  auditierbar und in `vault-storage` einfach transaktional zu halten.
- Kein Transport privater Ratchet-Schluessel zwischen Geraeten.

**Schwerer / Folgearbeiten:**

1. `spec/protokoll-spec.md` §9.3 neu fassen (geteilte Session entfaellt,
   Store-and-Forward und Send-Proxy beschreiben).
2. `spec/protokoll-spec.md` §9.2 um den `H(Envelope) → msg_id`-Cache und die
   Re-Ack-Regel ergaenzen (Befund F-3).
3. §9.1 `DeviceList` um ein Feld `primary_device_id` **je Kompartiment**
   erweitern; signiert von `IK`; Rollenwechsel als eigener Flow inkl.
   Zustandsuebergabe spezifizieren.
4. §9.4 praezisieren: nur das Primaergeraet erzeugt `Ack`.
5. UI/Design (P0-6): ehrliche Kennzeichnung „Senden erst moeglich, wenn
   <Primaergeraet> erreichbar ist" und ein verstaendlicher Rollenwechsel.
6. GATE-3 (Netzprofil): Ack-Zeitpunkt so festlegen, dass er kein feines
   Praesenzsignal des Primaergeraets erzeugt.
7. `spec/threat-model.md`: Zeile A4/G3 anpassen, Restrisiko R-11 aufnehmen.
8. Die 10.000-Lauf-Testsuite aus Spike S2 wird als Modelltest gegen
   `vault-delivery` weitergefuehrt (Massnahme zu Risiko R-3).
9. Spaeterer Migrationspfad A2 offenhalten: dazu ist in §8 eine stabile,
   senderseitig vergebene Nachrichten-ID vorzusehen, die von der
   Verschluesselung unabhaengig ist.
