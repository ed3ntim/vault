# ADR-21: Envelope-Cache mit geschlüsseltem `env_tag`, frisch verschlüsseltes Re-Ack, terminaler Zustand `EXPIRED`

- **Status:** akzeptiert
- **Datum:** 2026-09-02
- **Betrifft:** `spec/protokoll-spec.md` §1, §3, §8, §8.2, §9.2, §9.3, §9.4; `core/vault-crypto`,
  `core/vault-delivery`, `core/vault-storage`; ADR-05, ADR-17, ADR-19, ADR-20
- **Löst Gate:** keins (schließt offenen Punkt #2 aus ADR-17, Befund F-3)

## Kontext

Ein `Ack` kann verlorengehen. Stellt der Sender denselben Envelope erneut zu,
kann der Empfänger ihn **nicht mehr entschlüsseln**, weil der Message Key
verbraucht ist. Der Empfänger schweigt, der Sender wiederholt, der Empfänger
schweigt weiter: die Endlosschleife aus Befund F-3 (`spikes/S2/BERICHT.md`).

ADR-17 nennt als Folgearbeit einen Cache `H(Envelope) → msg_id` mit frischem
Re-Ack. Zwei Stellen daran sind nicht übernehmbar:

- `H(Envelope)` ist ein **roher** Hash über Bytes, die jeder sehen kann, der den
  Envelope sieht. Ein erbeuteter Cache wäre gegen mitgeschnittene Envelopes
  abgleichbar.
- `msg_id` ist nach ADR-20 als Bezeichner ersetzt.

`CLAUDE.md` setzt zugleich eine harte Schranke: „Zustellstatus `delivered`
ausschließlich nach echtem E2E-ACK." Ein Re-Ack darf diese Regel nicht
aufweichen.

## Entscheidung

1. **Envelope-Cache je Kontakt-Session, nur auf dem Primärgerät** (§9.3):
   ```
   k_env    = HKDF(DR_X.RK_initial, "vault-envelope-cache")   // einmal je Session
   env_tag  = HMAC(k_env, dr_header ‖ ciphertext)[0..16]      // lokal, nie auf der Wire
   Cache:     env_tag → msg_uid
   ```
   Geschlüsselt statt roh gehasht: ohne Sitzungsgeheimnis ist der Cache nicht
   gegen mitgeschnittene Envelopes prüfbar.
2. **Sechs verbindliche Regeln** (§9.3 Regeln 1 bis 6): Eintrag nach
   erfolgreicher Entschlüsselung; bei Entschlüsselungsfehler **mit** Cache-Treffer
   ein **frisch verschlüsseltes** `Ack { ref_uid = msg_uid }` aus dem aktuellen
   Sendezustand, ohne Verlaufseintrag, ohne `Receipt`, ohne `SyncRecord` und ohne
   Wiederverwendung eines alten Ack-Chiffrats; bei Entschlüsselungsfehler **ohne**
   Cache-Treffer stilles Verwerfen ohne jede Antwort auf der Wire;
   [`MAX_REACK_PER_ENTRY`] = 5 Re-Acks je Eintrag und Stunde, danach wie stilles
   Verwerfen; [`MAX_ENV_CACHE`] = 2048 Einträge je Session mit Verdrängung des
   ältesten Eintrags nach Einfügereihenfolge (FIFO), weil ein voller Cache sonst
   jede weitere Wiederholung der Session unbeantwortet ließe und damit genau die
   Schleife wiederherstellte, die dieser ADR beendet (dieselbe Politik wie in
   ADR-19, hier eigenständig begründet); kein Schlüsselmaterial, kein Klartext
   im Cache, `zeroize` bei Revocation.
3. **Persistenz** (§9.3 Regel 7): Cache und `k_env` liegen in der verschlüsselten
   Session-Ablage und überleben Neustarts. Ohne Persistenz fiele nach jedem
   App-Start jede Wiederholung unter Regel 3 und eine gelesene Nachricht liefe
   beim Sender in `EXPIRED`.
4. **Senderseitige Abbruchschranke** (§9.2): Die Wiederholung endet bei `Ack`
   mit `ref_uid == msg_uid` oder mit Ablauf der **einheitlichen** `queue_ttl`
   von **7 Tagen**, die für jeden Payload-Typ gleich ist. Die Anzeigefrist
   `disappear_after` (§8.2) verkürzt sie nicht: eine an die Nutzereinstellung
   gekoppelte Zustellfrist wäre am Wiederholungsverkehr ablesbar (A1/A2) und
   bräche bei kurzer Selbstlöschzeit die Zustellung ab, obwohl der Empfänger nur
   offline war.
5. **`EXPIRED` ist ein terminaler Zustand der Zustellstatus-FSM** (§9.4).
   Envelope und Nutzlast werden gelöscht, `msg_uid` bleibt bis zum Ende des
   Dedup-Fensters erhalten. Die UI zeigt „nicht zugestellt".
6. **`DELIVERED` setzt ausschließlich das Primärgerät nach einem echten
   E2E-`Ack`, auch wenn dieses ein Re-Ack nach Regel 2 ist** (§9.4). Das ist
   zulässig, weil ein Cache-Eintrag ausschließlich durch Regel 1 entsteht, also
   nur nach nachweislich einmal erfolgter Entschlüsselung, und weil das Re-Ack
   frisch aus dem Sendezustand verschlüsselt wird, also nicht fälschbar und nicht
   replaybar ist.
7. **Notation:** `HMAC` = HMAC-SHA-256 (RFC 2104 / FIPS 198-1) wird in §1
   nachgetragen, umgesetzt über etablierte Bibliotheken (`hmac` + `sha2`,
   RustCrypto), nicht selbst implementiert.
   **Dies ist ausdrücklich keine Erweiterung von ADR-05 durch diesen ADR.**
   Begründung: (a) `spec/protokoll-spec.md` §10 und §13 verwenden `HMAC` bereits
   im committeten Spec-Stand, dieser ADR führt es nicht ein, sondern benennt das
   Verfahren; (b) HMAC-SHA-256 ist der MAC, auf dem das von ADR-05 ohnehin
   verlangte HKDF-SHA-256 aufsetzt, also kein zusätzliches Vertrauensobjekt;
   (c) die Primitivenliste des Projekts steht faktisch in §1 der Protokoll-Spec,
   nicht in ADR-05, das nur PQXDH und Double Ratchet nennt.
   Die **formale** Frage, ob ADR-05 die Primitivenliste künftig selbst führen
   soll, ist an ed3n eskaliert (`ops/autopilot/ESKALATIONEN.md`, Eintrag vom
   2026-09-02 zu ADR-05). Fällt die Antwort gegen HMAC aus, sind §9.3, §10 und
   §13 gemeinsam betroffen, nicht nur dieser ADR.

## Alternativen

- **Roher `H(Envelope)` als Cache-Schlüssel** (Wortlaut ADR-17). Verworfen: für
  jeden berechenbar, der die Envelope-Bytes kennt, damit ein Abgleichsorakel
  gegen einen erbeuteten Cache. Der Aufpreis für `k_env` ist eine
  HKDF-Ableitung je Session.
- **Altes Ack-Chiffrat aufbewahren und erneut senden.** Verworfen: replaybares
  Bytemuster auf der Wire (A7/G1) und ein stabiler Wiedererkennungswert.
- **Message Key für Ack-Fälle vorhalten statt Cache.** Verworfen: hebelt Forward
  Secrecy aus, verletzt Priorität 1.
- **Fehlerantwort statt stillem Verwerfen bei Cache-Miss.** Verworfen: eine
  unterscheidbare Antwort ist ein Orakel für A7 und A4, mit dem sich Präsenz und
  Cache-Zustand abfragen ließen.
- **Unbegrenzte Wiederholung ohne `EXPIRED`.** Verworfen: genau die
  Endlosschleife aus F-3, sobald der Cache-Eintrag verdrängt ist, und ein
  unbegrenzt auf dem Gerät liegender unzustellbarer Envelope.
- **`DELIVERED` beim Re-Ack unterdrücken** (Status bliebe `WAITING`). Verworfen:
  die Nachricht **ist** nachweislich angekommen; ein dauerhaft falsches
  „wartet" widerspricht der Ehrlichkeitsregel in §9.4 genauso wie ein falsches
  „zugestellt".

## Auswirkung auf das Threat Model

**Pflichtfeld.**

- **A7/G1 (Replay):** unverändert ○. Ein Re-Ack ist immer frisch verschlüsselt;
  aufgezeichnete Ack-Chiffrate bleiben wertlos. Wiedereingespielte Envelopes
  erzeugen keinen Verlaufseintrag.
- **A7/G8 (gezielte Nichtzustellung, stiller Drop):** verbessert. Ein
  unterschlagenes Ack führt nicht mehr zu einer dauerhaft blockierten
  Wiederholungsschleife, sondern entweder zu Re-Ack und `DELIVERED` oder nach
  `queue_ttl` zu einem ehrlichen `EXPIRED`.
- **A4/G3 (Präsenz-Probing durch einen autorisierten Kontakt):** neues, aber
  begrenztes Signal. Ein Re-Ack ist eine Antwort auf einen wiederholten Envelope
  und damit ein Lebenszeichen. Begrenzt durch [`MAX_REACK_PER_ENTRY`] = 5 je
  Eintrag und Stunde und dadurch, dass Re-Acks demselben Ack-Zeitpunkt und
  Jitter unterliegen wie reguläre Acks (GATE-3). Restrisiko bleibt ◐, unverändert
  zur heutigen Bewertung von G3 unter A4.
- **A1/A2/A3 (passive Beobachter):** unverändert. `env_tag` wird nie übertragen,
  der Cache erzeugt keinen neuen Wire-Wert. Das Antwortverhalten bleibt aus
  Beobachtersicht ein gewöhnliches Ack.
- **A8 (Geräte-Angreifer):** out of scope (§1.3). Der persistierte Cache enthält
  weder Klartext noch Message Keys; `k_env` liegt in der verschlüsselten Ablage
  und wird bei Revocation gelöscht.
- Anonymitätsset (§2.9 Gesamtkonzept) unberührt: Parameter fest für alle Nutzer,
  nicht konfigurierbar.

## Auswirkung auf den Prioritätsstack

- **Priorität 1:** unberührt bis gestärkt. Kein neuer Wire-Wert, kein neues
  Orakel, keine verlängerte Lebensdauer von Schlüsselmaterial. Das zusätzliche
  Präsenzsignal ist rate- und jitterbegrenzt.
- **Priorität 2:** unberührt. Alles läuft lokal zwischen den beiden Endpunkten,
  keine dritte Instanz.
- **Priorität 3:** belastet. Ein persistenter Zustand mehr, 7 Tage Wartezeit bis
  `EXPIRED` und ein Statuswert mehr in der UI.

## Konsequenzen

**Leichter:** Verlorene Acks heilen selbst. Die Zustellstatus-FSM ist
vollständig: jeder Envelope endet in `DELIVERED`, `READ` oder `EXPIRED`.

**Schwerer:** `vault-storage` bekommt einen weiteren persistierten Sitzungsteil
mit `zeroize`-Pflicht. Die Ratenbegrenzung braucht eine Uhr, liegt also in der
Zustellschicht, nicht in `vault-crypto` (Schichtregel).

**Folgearbeiten:**
1. Envelope-Cache, Re-Ack, Abbruchschranke und `EXPIRED` implementieren
   (Backlog C11); Testfälle: verlorenes Ack heilt, Cache-Miss bleibt stumm,
   Ratenbegrenzung greift, `EXPIRED` nach `queue_ttl`, kein Re-Ack vom
   Zweitgerät.
2. Ack-Jitter-Parameter an GATE-3 (bereits als Folgearbeit aus ADR-17 geführt);
   Re-Acks fallen unter dieselben Parameter.
3. `spec/threat-model.md` §4: G3 unter A4 um den Re-Ack-Pfad als Quelle des
   Präsenzsignals ergänzen, Bewertung bleibt ◐ (eingearbeitet).
4. Feldumbenennung `Text { body, ttl }` → `Text { body, disappear_after }` in
   `core/vault-wire` mitziehen (Backlog C10); die Zustellschicht führt
   `queue_ttl` als eigenen, nicht aus der Payload stammenden Wert (Backlog C11).
