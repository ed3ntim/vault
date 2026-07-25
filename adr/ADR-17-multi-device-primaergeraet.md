# ADR-17: Multi-Device-Architektur — Primärgerät-Modell (Variante B)

- **Status:** akzeptiert
- **Datum:** 2026-07-25
- **Betrifft:** `spec/protokoll-spec.md` §2, §8, §9.1–§9.4, §10;
  `spec/gesamtkonzept.md` §2.6; `spec/threat-model.md` §4/A4;
  `core/vault-delivery`, `core/vault-crypto`, `core/vault-storage`,
  `core/vault-core`; ADR-07
- **Löst Gate:** GATE-2
- **Gate-Zuordnung:** **GATE-2 → ADR-17** (dieses Dokument). Die Nummerierung
  folgt der Reihenfolge der ADR-Erstellung, nicht der Gate-Nummer; GATE-1
  liegt in ADR-16, ADR-15 behandelt die Intro-Point-Rotation.

## Kontext

`spec/phase0-spikeplan.md` §2 (S2) fragt wörtlich: „Funktioniert paarweiser
Double-Ratchet-Sync zwischen eigenen Geräten robust, oder braucht es ein
Primärgerät-Modell?" — und begründet die Kritikalität: „Seit Wegfall der
Mailbox trägt Multi-Device die asynchrone Zustellung. Fehler führen zu
**Nachrichtenverlust oder Doppelentschlüsselung** — die schlimmste
Fehlerklasse."

Spike S2 hat beide Varianten auf identischen Seeds gemessen: 1000 Nachrichten
je Lauf, 2–3 Geräte, 5 Szenarioprofile, Rohdaten in `spikes/S2/data/`. Die
Kernzahlen wurden gegen diese Rohdaten nachgerechnet.

| Kriterium | Variante A (§9.3 im Wortlaut) | **Variante B (Primärgerät)** |
|---|---|---|
| Verluste in 10.000 Läufen | **415.090 / 10.000.000 = 4,151 %** | **0** |
| Duplikate | 0 | **0** |
| fehlerfreie Läufe | 3.488 von 10.000 | **10.000 von 10.000** |
| Konvergenz < 60 s | 92,72 % | 92,68 % |
| `skipped_message_keys` Gerät / Kontakt | 947 / 2000 (Kappungsgrenze) | **255 / 1220** |
| Läufe über der 1000er-Grenze (Kontaktseite) | 0,92 % | **0,08 %** |
| SyncRecords je Nachricht | 3,50 | **1,50** |
| verworfene Acks / Divergenzen | 4.159.750 / 20.437.171 | **1.450 / 0** |

Variante A verliert in allen Szenarioprofilen: clock-drift 5,550 %,
partition-mid-ratchet 5,457 %, long-offline 3,954 %, mixed 3,814 %,
concurrent 1,979 %. Eine Sensitivitätsreihe zeigt, dass es kein Tuning-Problem
ist: Anhebung der Wiederholungsobergrenze von 30 auf 200 senkt den Verlust von
3,856 % auf 0,634 %, **beseitigt ihn aber nicht**. Bei dreifacher Latenz
liegt A bei 3,925 %, B bei 0,000 %.

**Entscheidend für die Bewertung:** Variante A wurde unter der *günstigsten
denkbaren* Annahme simuliert — idealer, verzögerungsfreier Replikation
privater Ratchet-Schlüssel. Real wäre sie schlechter. **Die 4,151 % sind eine
untere Schranke des Schadens.**

Die Ursache ist strukturell und wurde im Unit-Test isoliert nachgewiesen: Der
Double Ratchet ist ein Zwei-Parteien-Protokoll; sein **Sendezustand ist nicht
replizierbar**. §9.3 verlangt zugleich, dass jedes empfangende Gerät quittiert
— damit senden zwangsläufig mehrere Geräte auf derselben Session, belegen
dieselbe Kettenposition, und der Message Key ist nach einmaligem Gebrauch
gelöscht. Das ist genau die Forward-Secrecy-Eigenschaft, die gewollt ist.

## Entscheidung

**Vault setzt für Multi-Device das Primärgerät-Modell um (Variante B).** Der
Fallback ist in `spec/phase0-spikeplan.md` §2 vorgesehen und wird hiermit
gezogen.

1. Je Kontakt existiert genau **ein** Double-Ratchet-Zustand, ausschließlich
   auf dem **Primärgerät** des Kompartiments. Kein anderes Gerät hält `RK`,
   `CKs`, `CKr` oder private Ratchet-Schlüssel dieser Session.
2. Zweitgeräte sind **Read-Through-Replikate**: Klartext-Verlauf und Metadaten
   über das paarweise Geschwister-Mesh, das unverändert bestehen bleibt.
   `SyncRecord` transportiert **keinen** Kontakt-Ratchet-Zustand mehr.
3. Die Geräteliste (§9.1) enthält weiterhin **alle** Geräte. Ein Zweitgerät
   nimmt Envelopes an und leitet sie als **opake Bytes** an das Primärgerät
   weiter; entschlüsseln kann es sie nicht.
4. **`delivered` setzt ausschließlich das Primärgerät**, nach erfolgreicher
   Entschlüsselung und angekommenem Ack (§9.4, `CLAUDE.md`). Ein Zweitgerät
   quittiert nie; bis dahin zeigt die Gegenseite `WAITING`.
5. Senden vom Zweitgerät läuft als **Send-Proxy** über das Primärgerät. Ist das
   Primärgerät unerreichbar, ist das Zweitgerät in dieser Session **nicht
   sendefähig** — die UI sagt das ausdrücklich statt es zu kaschieren.
6. Die Primärrolle ist **je Kompartiment** zugewiesen, nutzerseitig umsetzbar
   und wird per signiertem `DeviceListUpdate` propagiert.
7. Der Empfänger führt je Session einen Cache `H(Envelope) → msg_id` und
   beantwortet einen erneut zugestellten Envelope mit einem **frisch
   verschlüsselten** Ack, ohne erneute Entschlüsselung. Ohne diese Regel läuft
   ein Paar bei verlorenem Ack in eine Endlosschleife (Befund F-3).

## Alternativen

- **Variante A — geteilte Kontakt-Session nach §9.3 im Wortlaut.** Verworfen,
  gemessen untauglich (4,151 % Verlust als untere Schranke). Damit A überhaupt
  funktionieren könnte, müssten **private Ratchet-Schlüssel** zwischen Geräten
  repliziert werden — das höbe die Post-Compromise-Security für die gesamte
  Gerätemenge auf und widerspräche `spec/gesamtkonzept.md` §2.4.
- **A-reconcile — A plus Zustandssnapshot vom kanonischen Gerät**, also die in
  §9.3 skizzierte Reconciliation. Verworfen: gemessen **schlechter** als A
  (11,860 % Verlust in 600 Läufen). DH-Ratchet-Schritte sind nicht kommutativ;
  ein Snapshot ist beim Eintreffen bereits veraltet.
- **A2 (informativ mitgemessen):** 0 Verluste, aber 19.865 echte Duplikate
  (0,199 %) — verletzt das Kriterium „0 Duplikate" und damit die zweite Hälfte
  der schlimmsten Fehlerklasse.
- Ansätze aus `spec/gesamtkonzept.md` Anhang A werden nicht erneut aufgerollt.

## Auswirkung auf das Threat Model

**Pflichtfeld.**

- **Verschlechterung — A4/G3 „Präsenz-Probing als autorisierter Kontakt"
  (heute ◐).** Die heutige Gegenmaßnahme lautet „Multi-Device: nur *mindestens
  ein Gerät erreichbar*". Mit Variante B wird das Präsenzsignal **feiner**: Wer
  quittiert, ist immer dasselbe Gerät. Ein übernommener Kontakt lernt damit das
  Aktivitätsmuster **eines** Geräts statt der Vereinigung mehrerer. Dämpfung:
  Store-and-Forward über Zweitgeräte (das Signal „Envelope angenommen" bleibt
  gerätemengenweit) und Ack-Jitter — dessen Parameter gehören ins einheitliche
  Netzprofil und damit an **GATE-3**. Bewertung bleibt ◐, die Begründung ist
  aber zu ersetzen.
- **Verbesserung — Angriffsfläche für Sitzungsschlüssel.** Kontakt-Sitzungs-
  material liegt auf **einem** statt auf N Geräten. Ein kompromittiertes
  Zweitgerät gibt keine Kontakt-Session preis. Das mindert den Schaden bei
  Geräteverlust — der zwar laut §1.1 außerhalb des Scopes liegt, aber hier
  ohne Gegenleistung besser wird.
- **Verbesserung — G8 (Verfügbarkeit/Zustellbarkeit).** „Stiller Verlust ist
  gefährlicher als Mitlesen": Variante A erzeugte genau diesen stillen Verlust
  in 4,151 % der Fälle. B misst 0.
- **Neues Restrisiko R-11: Ausfall oder Verlust des Primärgeräts.** Solange
  kein Rollenwechsel stattgefunden hat, ist das Kompartiment in dieser Session
  nicht sendefähig. Der Rollenwechsel selbst ist **ungetestet** und braucht
  einen eigenen Spike, bevor Phase 2 ihn implementiert.
- **Anonymitätsset (§2.9):** unberührt. Das Modell gilt für alle Nutzer gleich;
  es entsteht keine wählbare Variante.

## Auswirkung auf den Prioritätsstack

- **Priorität 1 (Anonymität und Datenschutz):** berührt, aber **nicht
  verletzt** — feineres Präsenzsignal gegenüber einem bereits autorisierten
  Kontakt, kompensiert durch Store-and-Forward und Ack-Jitter, im Gegenzug
  kleinere Angriffsfläche für Sitzungsschlüssel.
- **Priorität 2 (Serverlosigkeit):** unberührt. Das Primärgerät ist ein eigenes
  Gerät des Nutzers, kein Dritter und kein Betreiberdienst — ADR-07 bleibt
  gewahrt.
- **Priorität 3:** belastet — Zweitgerät ohne Primärgerät eingeschränkt
  sendefähig. Genau der in der Spec vorgesehene Preis des Fallbacks.

## Konsequenzen

**Leichter:** 1,50 statt 3,50 SyncRecords je Nachricht, keine Divergenzen,
keine vergeblichen Entschlüsselungsversuche; deutlich einfacheres Zustandsmodell
und damit testbarer.

**Schwerer:** Eine Rolle mehr im Datenmodell; der Rollenwechsel wird zum
kritischen Pfad für die Verfügbarkeit; die UI muss den Zustand „nicht
sendefähig" ehrlich anzeigen.

**Folgearbeiten:**
1. `spec/protokoll-spec.md` §9.3 ändern — der geteilte Kontakt-Session-Zustand
   mit `dr_delta`-Replikation entfällt. **Offener Punkt, bewusst noch nicht
   eingearbeitet; wird gemeinsam formuliert.**
2. §9.2/§9.3 um den Cache `H(Envelope) → msg_id` mit frischem Re-Ack ergänzen
   (F-3). **Offener Punkt.**
3. §8: `msg_id` taugt nicht als geräteübergreifender Dedup-Schlüssel (F-2) —
   Dedup-Schlüssel neu festlegen. **Offener Punkt.**
4. Erfolgskriterium „Konvergenz < 60 s nach Wiederverbindung" präzisieren; es
   ist serverlos in der jetzigen Formulierung von keiner Variante erfüllbar
   (Folge von ADR-07), gemessen 92,7 %. **Offener Punkt.**
5. `spec/threat-model.md` §4/A4-G3: Begründung der ◐-Bewertung ersetzen.
6. Eigener Spike für Rollenwechsel und Primärgeräteverlust (R-11), vor der
   Umsetzung in Phase 2.
7. Ack-Jitter-Parameter an GATE-3 übergeben.
