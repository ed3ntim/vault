# Vault Messenger — Arbeitsregeln

## Was das ist
Serverloser, anonymitaetsmaximierter Messenger. Primaerer Gegner: staatliche
Nachrichtendienste. Alle Entwurfsentscheidungen sind getroffen und liegen
in spec/. Deine Aufgabe ist Umsetzung, nicht Neuentwurf.

## Normative Dokumente (in dieser Rangfolge)
1. spec/gesamtkonzept.md — Architektur, Prioritaeten, Anhang A (verworfene Ansaetze)
2. spec/protokoll-spec.md — Formate, Handshake, Zustellung, Revocation, Mesh
3. spec/gruppen-spec.md — MLS, Sequencer, Attestation, Pairwise
4. spec/threat-model.md — Angreiferklassen, Assets, Restrisiken
5. spec/phase0-spikeplan.md — Spikes, Gates, Risiken
6. spec/engineering-setup.md — ADRs, Repo-Struktur, CI-Gates, MVP
7. adr/ — Architecture Decision Records, verbindlich

Bei Widerspruch zwischen Code und Spec gewinnt die Spec.
Bei Widerspruch zwischen Specs gewinnt die niedrigere Nummer.

## Prioritaetsstack (loest jeden Zielkonflikt)
1. Anonymitaet und Datenschutz
2. Serverlosigkeit
3. Alles andere (Komfort, Latenz, Features) — opferbar

Wenn eine Aufgabe nur loesbar ist, indem Prioritaet 1 oder 2 verletzt wird:
NICHT umsetzen, sondern melden.

## Unverhandelbar
- Kein Netzwerkverkehr ausserhalb von Tor bzw. lokalem Mesh. Kein HTTP-Client,
  keine Analytics, kein Crash-Reporting, kein Telemetrie-Backend (ADR-14).
- Keine eigenen Kryptoprimitive. Nur die in ADR-05 festgelegten Verfahren
  ueber etablierte Bibliotheken.
- Kein Verzeichnis, keine Usernamen, keine Server, keine Mailbox.
  Anhang A des Gesamtkonzepts listet alle verworfenen Ansaetze — sie bleiben
  verworfen und werden nicht erneut vorgeschlagen.
- Keine Schluessel, Onion-Adressen, Kontakt-IDs oder Klartexte in Logs.
- forbid(unsafe_code) ueberall ausser vault-ffi und Transport-Bindings.
- Schluesselmaterial mit zeroize, Vergleiche konstantzeitig (subtle).
- Kein unwrap()/expect() in Bibliothekscode.
- Zustellstatus "delivered" ausschliesslich nach echtem E2E-ACK.

## Schichtregel (CI-geprueft)
- vault-crypto: keine I/O, keine Netzabhaengigkeiten
- vault-transport: kennt keine Klartext-Payloads
Verstoesse brechen den Build. Nicht umgehen.

## Arbeitsweise
- Jede Aufgabe: erst Spec-Abschnitt lesen und zitieren, dann Testfaelle
  schreiben, dann implementieren, dann verifizieren.
- Jede sicherheitsrelevante Aenderung verweist im Commit auf Spec-Abschnitt
  oder ADR.
- Abweichung von der Spec nur mit neuem ADR in adr/ — mit Begruendung,
  Alternativen und Auswirkung auf das Threat Model.

## Verbotene Abkuerzungen
- Tests deaktivieren, ueberspringen oder aufweichen, damit etwas gruen wird
- CI-Gates umgehen
- Sicherheitspruefungen auskommentieren "fuer spaeter"
- Platzhalter-Krypto ("TODO: richtige Verschluesselung")
- Netzwerkaufrufe hinzufuegen, um ein Problem zu umgehen
Wenn etwas nicht anders loesbar scheint: melden statt umgehen.

## Wann du stoppst und fragst
- Spec ist mehrdeutig oder lueckenhaft
- Zwei Specs widersprechen sich
- Die saubere Loesung verletzt Prioritaet 1 oder 2
- Ein Spike scheitert an seinem Erfolgskriterium
- Ein Sicherheits-Trade-off waere noetig, der nicht in der Spec steht
Melde dann: Problem, Optionen, deine Empfehlung, Auswirkung auf das
Threat Model. Entscheide nicht selbst.

## Berichtsformat nach jeder Aufgabe
1. Was umgesetzt wurde (mit Spec-Referenz)
2. Testergebnisse (welche, wie viele, was abgedeckt)
3. Was nachweislich funktioniert vs. was nur kompiliert
4. Offene Punkte und getroffene Annahmen
5. Naechster sinnvoller Schritt
Keine Erfolgsmeldung ohne bestandene Tests.
