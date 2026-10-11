# ADR-19: FIFO-Verdrängung im Skipped-Message-Key-Store

- **Status:** **akzeptiert** (Freigabe 2026-09-02 durch den `business-analyst`
  im Rahmen seiner Befugnis für Sicherheits-Trade-offs ohne Berührung von
  Priorität 1 oder 2; Begründung unten unter „Freigabe", Entscheidungslog
  `ops/autopilot/ENTSCHEIDUNGEN.md`. Entwurfsstand vom 2026-07-26.)
- **Datum:** 2026-07-26, freigegeben 2026-09-02
- **Betrifft:** `core/vault-crypto` (`ratchet`), `spec/protokoll-spec.md` §8,
  `spec/phase0-spikeplan.md` §2 (S2), `spec/threat-model.md` §4/A7;
  ADR-05, ADR-17
- **Löst Gate:** — (schließt Befund HOCH-2 des unabhängigen Gegenlesens)

## Kontext

Der Double Ratchet hält Message Keys für übersprungene Nachrichten vor, damit
out-of-order zugestellte Frames noch geöffnet werden können.
`spec/phase0-spikeplan.md` §2 (S2) nennt dazu **eine** Zahl:

> „`skipped_message_keys` < 1000 pro Session (Speicherobergrenze)"

**Die Spec sagt nicht, was beim Erreichen der Grenze passiert.** Die
Implementierung lehnte bisher neue Einträge ab. Das unabhängige Gegenlesen
hat gemessen, wohin das führt:

```
Angreifer unterschlägt m0..m998, stellt m999 zu   → ok, skipped_len() == 999
m1000 in Reihenfolge                              → ok
m1001 fällt aus, m1002 kommt an                   → Err(SkippedKeyLimitExceeded)
```

Ab diesem Punkt ist **jede** out-of-order zugestellte Nachricht dauerhaft
unzustellbar; nur noch lückenloser Verkehr funktioniert. Der Store schrumpft
ausschließlich, wenn ein übersprungener Key eingelöst wird — die
unterschlagenen Nachrichten kommen aber nie. Ein DH-Ratchet-Schritt heilt es
nicht, weil `skipped` dort nicht angefasst wird.

**Aufwand für den Angreifer: einmalig. Wirkung: permanent.** Das ist dasselbe
Aufwandsprofil, gegen das der try-then-commit-Umbau in `decrypt` schützt.
`spec/threat-model.md` führt A7/G8 („Gezielte Nichtzustellung / stiller
Drop") mit Restrisiko **○** und begründet das mit „Zustellstatus **nur** über
E2E-ACK; persistente Retry-Queue" — beides hilft nicht, wenn der Empfänger
strukturell nicht mehr entschlüsseln kann.

Auf welchen Transporten das realistisch ist: Mesh (§13) und
Multi-Onion-Routing (§9.2) geben keine Reihenfolgegarantie; eine längere
Offline-Phase des Empfängers reicht bereits, um den Vorrat zu füllen.

## Entscheidung

**Der Skipped-Store verdrängt nach FIFO, statt neue Einträge abzulehnen.**
Ist der Store voll, verdrängt ein neuer Message Key den **ältesten
ungenutzten**.

1. Die Obergrenze [`MAX_SKIPPED_STORED`] (999, aus S2) bleibt unverändert und
   gilt als harte Speichergrenze.
2. Beim Einfügen in einen vollen Store wird der Eintrag mit der ältesten
   Einfügereihenfolge entfernt. Maßgeblich ist die **Einfügereihenfolge**,
   nicht die Nachrichtennummer — nach einem DH-Ratchet-Schritt beginnen die
   Nummern wieder bei 0, eine Sortierung nach Nummer würde die falschen
   Einträge treffen.
3. [`MAX_SKIP_PER_CHAIN`] (1000 je Kette) bleibt als eigene Schranke
   bestehen: Sie begrenzt den Rechenaufwand je Frame, nicht den Speicher.
4. `SkippedKeyLimitExceeded` bleibt für die Per-Kette-Schranke erhalten und
   entfällt als Fehler beim Speicherlimit.

### Begründung

- **Verfügbarkeit (G8).** Der permanente Total-DoS entfällt. Das ist der
  eigentliche Grund; „stiller Verlust ist gefährlicher als Mitlesen"
  (`threat-model.md` §3).
- **Forward Secrecy wird nicht schlechter, sondern besser.** Das ist der
  Punkt, an dem die naheliegende Intuition täuscht: Man könnte meinen,
  Verdrängung halte Schlüssel länger vor. Das Gegenteil ist der Fall — beim
  Ablehnen bleiben die 999 vorhandenen Keys **unbegrenzt** liegen, weil nur
  ihre Einlösung sie entfernt. Bei FIFO wird jeder alte Key aktiv gelöscht,
  sobald neuer Verkehr eintrifft. Der Vorrat rotiert statt zu horten.
- **Preis:** Eine sehr alte, nach mehr als 999 zwischenzeitlichen
  Übersprungenen doch noch eintreffende Nachricht ist nicht mehr lesbar. Sie
  ist damit genauso verloren wie heute — nur betrifft es künftig **diese
  eine** Nachricht statt aller nachfolgenden.
- **Signal-Referenz** verdrängt ebenfalls die ältesten Einträge; ADR-05
  verlangt Verfahren nach etablierter Spezifikation.

## Alternativen

- **Ablehnen (Status quo).** Verworfen: erzeugt den permanenten DoS aus
  HOCH-2 und hortet zugleich Message Keys unbegrenzt lange. Schlechter in
  **beiden** Dimensionen.
- **Zusätzliche Lebensdauer je Eintrag (TTL).** Nicht verworfen, aber hier
  nicht entschieden: Eine TTL braucht eine Zeitquelle, und `vault-crypto`
  darf nach der Schichtregel kein I/O und keine Uhr benutzen. Sie gehörte
  in die aufrufende Schicht. **Offene Frage unten.**
- **Store beim DH-Ratchet-Schritt leeren.** Verworfen: Genau die
  kettenübergreifenden Lücken sind der Regelfall bei Richtungswechseln; das
  Leeren würde legitime Nachrichten verwerfen.

## Auswirkung auf das Threat Model

**Pflichtfeld.**

- **A7/G8 („Gezielte Nichtzustellung / stiller Drop", heute ○):** Die
  Bewertung ○ ist ohne diese Entscheidung **nicht haltbar** — HOCH-2 ist ein
  Weg zum permanenten Zustellausfall mit einmaligem Aufwand. Mit
  FIFO-Verdrängung wird ○ wieder tragfähig, sobald der Regressionstest
  `voller_store_blockiert_die_session_nicht` grün ist.
- **A1/G1 (Forward Secrecy, ○):** verbessert, siehe Begründung. Kein
  Trade-off.
- **A7/G1 („Replay alter Nachrichten", ○):** unverändert. Verdrängte Keys
  sind gelöscht, ein späterer Replay findet nichts mehr.
- **Anonymitätsset (§2.9):** unberührt; die Politik ist fest und für alle
  Nutzer gleich.

## Auswirkung auf den Prioritätsstack

- **Priorität 1:** unberührt bis leicht gestärkt (kürzere Lebensdauer alter
  Message Keys).
- **Priorität 2:** unberührt.
- **Priorität 3:** minimal belastet — eine zusätzliche Einfügereihenfolge im
  Zustand.

## Konsequenzen

**Leichter:** Der Empfänger kann nicht mehr dauerhaft verklemmt werden; der
Speicher bleibt hart gedeckelt.

**Schwerer:** Der Ratchet-Zustand braucht eine Einfügereihenfolge zusätzlich
zur Map. Beim Persistieren (`vault-storage`) muss diese Reihenfolge
mitgeschrieben werden, sonst ändert sich das Verdrängungsverhalten nach einem
Neustart.

**Folgearbeiten:**
1. `spec/protokoll-spec.md` §8 um die Verdrängungspolitik ergänzen — die
   Spec nennt bisher nur die Zahl. **Offener Punkt #9.**
2. `spec/phase0-spikeplan.md` §2 (S2): das Erfolgskriterium prüft die
   Speicherobergrenze; es sollte zusätzlich verlangen, dass die Session bei
   vollem Vorrat benutzbar bleibt.
3. Persistenz der Einfügereihenfolge in `vault-storage` (verwandt mit
   offenem Punkt #10, Ratchet-Rollback).

## Offene Fragen

1. **TTL zusätzlich zur FIFO-Verdrängung?** Ohne Zeitquelle in
   `vault-crypto` müsste die aufrufende Schicht sie durchreichen. Lohnt der
   Aufwand, wenn FIFO das Horten bereits beendet?
   → **Entschieden 2026-09-02: nein, nicht im MVP.** `vault-crypto` darf nach
   der Schichtregel keine Uhr benutzen, und FIFO beendet das Horten bereits.
   Eine TTL in der Zustellschicht bleibt als spätere Option offen und ist kein
   Freigabehindernis.
2. **Soll die Verdrängung beobachtbar sein?** Ein Zähler „wie viele Keys
   wurden verdrängt" wäre ein Indikator für einen laufenden Angriff, aber
   auch ein Metadatum, das irgendwo landen müsste.
   → **Entschieden 2026-09-02: kein persistierter Zähler, keine Logausgabe.**
   Ein prozesslokaler Zähler ist ausschließlich in Tests zulässig. Begründung:
   ein persistiertes Angriffsindiz ist ein Metadatum über den Nutzer, und
   `CLAUDE.md` verbietet Metadaten dieser Art im Log; Priorität 1 schlägt den
   diagnostischen Nutzen.

## Freigabe (2026-09-02)

Geprüft gegen den Prioritätsstack: Priorität 1 wird nicht berührt, sondern
leicht gestärkt (alte Message Keys rotieren statt zu lagern); Priorität 2 ist
nicht betroffen, der Store ist rein lokal. Es kehrt kein Ansatz aus Anhang A
zurück, es entsteht kein eigenes Kryptoprimitiv, kein Netzverkehr, keine Bindung
an Dritte. Die Datengrundlage (Befund HOCH-2, reproduzierter Ablauf im
Kontextabschnitt) liegt vor; die beiden offenen Fragen sind oben entschieden und
waren ohnehin keine Voraussetzung der Kernentscheidung. Damit ist die Politik
zitierfähig: `spec/protokoll-spec.md` §8.1 und §9.3 verweisen auf sie als
Verdrängungspolitik, begründen sie dort aber zusätzlich eigenständig.
