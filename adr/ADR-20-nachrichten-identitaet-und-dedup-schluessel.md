# ADR-20: Nachrichten-Identität `msg_uid` als Dedup-Schlüssel, `env_ref` nur lokal

- **Status:** akzeptiert
- **Datum:** 2026-09-02
- **Betrifft:** `spec/protokoll-spec.md` §8, §8.1, §9.2, §9.3; `core/vault-wire`
  (`envelope.rs`), `core/vault-crypto` (`hash.rs`), `core/vault-delivery`;
  ADR-05, ADR-17
- **Löst Gate:** keins (schließt offenen Punkt #3 aus ADR-17, Befund F-2)

## Kontext

`spec/protokoll-spec.md` §8 führte bisher **einen** Bezeichner:

> `msg_id = H(dr_header ‖ ciphertext)`

Der Spike S2 hat dazu zwei Befunde geliefert (`spikes/S2/BERICHT.md`, F-2):

1. `msg_id` hängt am **Chiffrat**. Dieselbe Nachricht, für ein anderes Zielgerät
   neu verschlüsselt oder nach einem Ratchet-Schritt erneut erzeugt, ergibt einen
   anderen Wert. Als geräteübergreifender Dedup-Schlüssel ist er damit untauglich.
2. Die Spec nannte `msg_id` „nur innerhalb der entschlüsselten Sicht", er ist
   aber aus den Wire-Bytes von jedem berechenbar, der den Envelope sieht. Als
   Geheimnis taugt er nicht.

Unter ADR-17 (Primärgerät-Modell) entschärft sich Fall 1 nicht: Zweitgeräte
reichen opake Bytes weiter, das Primärgerät entschlüsselt, und der Sender
verschlüsselt beim Zielgerätewechsel neu. Ohne klartextseitige Kennung erkennt
der Empfänger dieselbe Nachricht zweimal nicht wieder und schreibt sie doppelt
in den Verlauf.

## Entscheidung

**Zwei Bezeichner mit getrennter Aufgabe, nicht austauschbar** (`protokoll-spec.md` §8.1):

1. **`msg_uid`, 16 B, Identität der Nachricht.** Vom Sender einmal bei der
   Komposition aus dem CSPRNG gezogen, danach unverändert über alle
   Zustellversuche, Neuverschlüsselungen, Zielgeräte, Transporte und
   Ratchet-Schritte. Liegt im AEAD-geschützten Klartext, erscheint nie auf der
   Wire. Jede Payload trägt genau eine `msg_uid`; `Ack` und `Receipt` verweisen
   mit `ref_uid` auf die quittierte `msg_uid`.
2. **`env_ref = H(dr_header ‖ ciphertext)`, Referenz auf genau ein Chiffrat.**
   Rein lokal, nie übertragen, **kein** Dedup-Schlüssel. Einzige Verwendung:
   der Envelope-Cache in §9.3 (dort in geschlüsselter Form als `env_tag`,
   ADR-21).
3. **Dedup-Schlüssel ist `(compartment_id, contact_id, msg_uid)`.** Der Store
   fasst [`MAX_DEDUP_UIDS`] = 2048 Einträge je Session und verdrängt bei
   Überlauf den Eintrag mit der ältesten Einfügereihenfolge (FIFO). Verdrängen
   statt Ablehnen, weil ein voller Store sonst jede weitere Nachricht der
   Session blockiert und ein Angreifer diesen Zustand mit einmaligem Aufwand
   dauerhaft herstellen könnte (A7/G8). ADR-19 entscheidet dieselbe Frage für
   den Skipped-Message-Key-Store gleich; die Begründung hier steht für sich.
   Eine bereits enthaltene
   `msg_uid` wird nicht erneut in Verlauf, UI oder `SyncRecord` übernommen, wohl
   aber nach §9.3 quittiert.
4. `msg_uid` wird **zufällig** gezogen, nicht aus dem Inhalt abgeleitet.

### Begründung

- Nur ein Bezeichner, der weder von der Verschlüsselung noch vom Zielgerät
  abhängt, kann geräteübergreifend deduplizieren. Das ist der Kern von F-2.
- Eine Ableitung aus dem Klartext (`H(pt)`) wäre bequemer, erlaubte aber einem
  Angreifer mit vermutetem Klartext die Existenzbestätigung. 16 B CSPRNG kostet
  nichts und schließt das aus.
- 16 B statt 32 B: die Kollisionswahrscheinlichkeit ist innerhalb einer Session
  vernachlässigbar, und der Wert liegt in jeder Payload, also im
  Größenbudget der Größenklassen (§2.5 Gesamtkonzept).

## Alternativen

- **Nur `msg_id` behalten, Retry immer bitidentisch wiederholen.** Verworfen:
  erzwingt, dass der Sender das Chiffrat für jedes Zielgerät aufbewahrt, und
  kollidiert mit dem Re-Ack-Fall (ADR-21). Löst F-2 nicht, sondern verbietet den
  Zielgerätewechsel.
- **`msg_uid` aus dem Klartext ableiten** (`H(pt ‖ salt)`). Verworfen: ohne
  Sender-Salt ein Bestätigungsorakel, mit Salt funktional identisch zu Zufall,
  aber komplizierter.
- **Sequenznummer je Session statt Zufall.** Verworfen: eine monotone Nummer im
  Klartext verrät dem Empfänger und jedem, der später an den entschlüsselten
  Bestand kommt, die Gesamtzahl der Nachrichten und erlaubt Lückenanalyse.
- **Dedup ganz weglassen.** Verworfen: Doppelte im Verlauf sind laut
  `threat-model.md` §3 die zweitschlimmste Fehlerklasse nach stillem Verlust.

## Auswirkung auf das Threat Model

**Pflichtfeld.**

- **A1/A2/A3 (passive Beobachter, Tor-Infrastruktur):** unverändert. `msg_uid`
  liegt im AEAD-Klartext und ist auf der Wire nicht sichtbar; `env_ref` wird nie
  übertragen. Es entsteht **kein** neuer stabiler Wire-Identifier, insbesondere
  keine Verkettbarkeit über Transportgrenzen (`transport_tag` bleibt ephemer,
  §8).
- **A4 (übernommener Kontakt):** kennt den Klartext ohnehin; `msg_uid` gibt ihm
  nichts Zusätzliches. Er kann Nachrichten derselben Session verketten, was er
  über den Inhalt bereits kann.
- **A7 (aktiver Netzangreifer, G1 Replay):** verbessert. Wiedereingespielte
  Envelopes werden über den Dedup-Store zuverlässig als Duplikat erkannt, auch
  wenn das Chiffrat neu ist.
- **A8 (Geräte-Angreifer):** out of scope (§1.3). Der Dedup-Store liegt in der
  verschlüsselten Ablage und enthält keine Klartexte.
- Kein neues Restrisiko. Anonymitätsset (§2.9 Gesamtkonzept) unberührt: die
  Politik ist fest und für alle Nutzer gleich.

## Auswirkung auf den Prioritätsstack

- **Priorität 1:** leicht gestärkt, weil der bisherige, aus Wire-Bytes für jeden
  berechenbare Bezeichner seine tragende Rolle verliert.
- **Priorität 2:** unberührt, rein lokale Zustandshaltung.
- **Priorität 3:** 16 B je Payload und ein zusätzlicher Store je Session.

## Konsequenzen

**Leichter:** Dedup funktioniert über Zielgerätewechsel, Neuverschlüsselung und
Transportwechsel hinweg. `Ack`/`Receipt` referenzieren stabil.

**Schwerer:** Wire-Format-Änderung. `core/vault-wire` führt heute
`Ack { msg_id: [u8; 32] }` und `Receipt { msg_id: [u8; 32] }`; das wird zu
`Payload { msg_uid: 16B, body }` mit `Ack { ref_uid }` / `Receipt { ref_uid, kind }`.
`core/vault-crypto` (`hash.rs`) benennt `msg_id` in `env_ref` um und dokumentiert
sie als rein lokal.

**Folgearbeiten:**
1. `core/vault-wire` an §8/§8.1 anpassen, inkl. Determinismus-Testvektoren
   (Backlog C10).
2. Dedup-Store mit FIFO-Politik in `core/vault-delivery` bzw. `vault-storage`
   (Backlog C11).
3. `spikes/S2` bleibt unverändert stehen: der Simulator misst den alten Zustand
   und ist Beleg für F-2, kein Implementierungsziel.
