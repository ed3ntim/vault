# Offene Punkte aus ADR-15, ADR-16, ADR-17

Arbeitsvorrat. Diese Punkte sind **bewusst noch nicht** in die Specs
eingearbeitet — sie werden gemeinsam formuliert. Erledigte Punkte werden hier
auf `erledigt` gesetzt und mit dem Commit verlinkt, nicht gelöscht.

| # | Punkt | Betroffenes Dokument / Abschnitt | Quelle | Status |
|---|---|---|---|---|
| 1 | Geteilter Kontakt-Session-Zustand mit `dr_delta`-Replikation entfällt; `SyncRecord` trägt keinen Kontakt-Ratchet-Zustand mehr | `spec/protokoll-spec.md` §9.3 | ADR-17 | **erledigt, Commit acbb1c8** |
| 2 | Cache `H(Envelope) → msg_id` mit frisch verschlüsseltem Re-Ack ergänzen; ohne diese Regel läuft ein Paar bei verlorenem Ack in eine Endlosschleife (Befund F-3) | `spec/protokoll-spec.md` §9.2, §9.3 | ADR-17 | offen |
| 3 | `msg_id` taugt nicht als geräteübergreifender Dedup-Schlüssel (Befund F-2); Dedup-Schlüssel neu festlegen | `spec/protokoll-spec.md` §8 | ADR-17 | offen |
| 4 | Erfolgskriterium „Konvergenz < 60 s nach Wiederverbindung" präzisieren — serverlos in der jetzigen Formulierung von keiner Variante erfüllbar (gemessen 92,7 %), Folge von ADR-07 | `spec/phase0-spikeplan.md` §2 (S2) | ADR-17 | **erledigt, Commit acbb1c8** |
| 5 | Erzwungene Intro-Point-Rotation bei Revocation aufnehmen, inkl. „wirksam erst nach bestätigter Rotation" | `spec/protokoll-spec.md` §11 | ADR-15 | offen |
| 6 | A4 „Weiterbestehender Zugriff nach Enttarnung" von ○ auf ◐ setzen, bis Spike S3 die Wirksamkeit der Rotation belegt | `spec/threat-model.md` §4/A4 | ADR-15 | offen |
| 7 | „Onion-Aufbau" definieren — Dienst erreichbar vs. Client verbunden; beide Lesarten messen Verschiedenes | `spec/phase0-spikeplan.md` §2 (S1) | ADR-16 | offen |
| 8 | (a) Bezugsgröße von „< 8 %/24 h" festlegen: R3−R0 oder R4−R0 — dieselben Daten bestehen unter der einen Lesart und reißen unter der anderen. (b) Kontakt- und Kompartimentzahl des Messprofils festlegen, weil der Verbrauch damit skaliert | `spec/phase0-spikeplan.md` §2 (S5) | Spike S5 (`spikes/S5/BERICHT.md`) | offen |

## Nicht in dieser Liste

Folgearbeiten, die **Arbeit** und keine Dokumentenänderung sind, stehen in den
ADRs selbst und nicht hier: S1-Nachzug auf Linux/Android inkl. C-tor-Prüfung
(ADR-16), Spike S3 zur Revocation-Latenz (ADR-15), eigener Spike für
Rollenwechsel und Primärgeräteverlust R-11 (ADR-17), Ack-Jitter-Parameter an
GATE-3 (ADR-17), Adaptermodul mit Vertragstests (ADR-16).
