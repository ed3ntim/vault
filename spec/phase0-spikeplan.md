# Vault Messenger — Phase 0: Arbeitspaket & Spike-Plan

**Ziel von Phase 0:** Alle Annahmen prüfen, die das Design tragen — **bevor** Produktionscode entsteht. Ein Spike ist erfolgreich, wenn er eine Entscheidung ermöglicht, nicht wenn er funktioniert.

**Dauer:** 8 Wochen · **Grundsatz:** Jeder Spike ist zeitlich hart begrenzt. Läuft die Box ab, gilt der Fallback.

---

## 1. Übersicht

| ID | Thema | Timebox | Blockiert | Kritikalität |
|---|---|---|---|---|
| S1 | Arti vs. C-tor: Onion-Service mit Client-Auth | 10 T | gesamten Transport | 🔴 kritisch |
| S2 | Multi-Device-Ratchet-Sync | 10 T | Zustellmodell | 🔴 kritisch |
| S3 | Revocation-Latenz (Descriptor-Republish) | 3 T | Sicherheitsversprechen | 🟠 hoch |
| S4 | HSDir-Publikations-Timing vs. Präsenzschutz | 5 T | Präsenzschutz | 🟠 hoch |
| S5 | Akku unter Dauer-Onion + Snowflake + Mesh | 8 T | Mobil-Tragfähigkeit | 🔴 kritisch |
| S6 | Invitation-Größe vs. QR-Kapazität | 2 T | Onboarding-UX | 🟡 mittel |
| S7 | Deterministisches CBOR über alle Bindings | 3 T | Signaturkonsistenz | 🟠 hoch |
| G1 | `openmls`-Reife für serverlosen Betrieb | 8 T | Gruppen-Modus | 🟠 hoch |
| G2 | Fan-out-Performance über Tor (20–50 Mitglieder) | 5 T | Gruppengrößen-Limit | 🟡 mittel |
| G3 | Epochen-Retention für offline Mitglieder | 3 T | Gruppen-Usability | 🟡 mittel |
| G4 | Removal-Quorum: Schwelle vs. Nutzbarkeit | 3 T | Gruppen-Sicherheit | 🟡 mittel |
| G5 | Attestation-Volumen bei großen Gruppen | 3 T | Skalierung | 🟡 mittel |
| E1 | Flutter↔Rust FFI: Durchsatz & Speicherverhalten | 5 T | UI-Architektur | 🟠 hoch |
| E2 | SQLCipher + Plattform-Keystore auf 4 Plattformen | 5 T | Storage | 🟠 hoch |
| E3 | Reproducible Build über 4 Plattformen | 8 T | Lieferkette | 🟠 hoch |

Parallelisierbar auf 4 Personen. Kritischer Pfad: **S1 → S5 → S2**.

---

## 2. Kritische Spikes im Detail

### S1 — Tor-Stack: Arti vs. C-tor

**Frage:** Unterstützt Arti Onion-Services **mit v3 Client Authorization** produktionsreif? Falls nein, ist C-tor sandboxed über 4 Plattformen einbettbar?

**Warum kritisch:** Client-Auth ist die tragende Säule des Präsenz- und Enumerationsschutzes (Threat Model A3). Ohne sie fällt das halbe Sicherheitsversprechen.

**Methode:**
1. Arti aus aktuellem Stand bauen; Onion-Service mit `authorized_clients` aufsetzen
2. Autorisierter Client verbindet ✓ / nicht-autorisierter Client scheitert ✓
3. Descriptor-Abruf durch Dritte muss fehlschlagen (mit eigenem HSDir-Beobachter prüfen)
4. Parallel: C-tor als Subprozess mit seccomp-Sandbox auf Android/Windows/Linux
5. Speicher-, Start- und Verbindungszeiten messen

**Erfolgskriterien:**
- Client-Auth funktional auf **allen** Zielplattformen
- **`T_conn` (Client verbunden)** < 20 s (p50), < 60 s (p95)
- **`T_pub` (Dienst erreichbar)** wird je Plattform gemessen und berichtet; die Schranke setzt GATE-1 auf Basis dieser Daten, sie wird hier nicht vorweggenommen
- Nicht-autorisierter Descriptor-Abruf schlägt in 100 % der Versuche fehl

**Messdefinition „Onion-Aufbau" (verbindlich, Entscheidung 2026-09-02):** Die
Formulierung „Onion-Aufbau" ist in zwei getrennte, beobachtbare Größen
aufgelöst. Beide werden gemessen, das Latenzkriterium trägt `T_conn`.

| Größe | Start (beobachtbar) | Stopp (beobachtbar) |
|---|---|---|
| `T_pub` | Aufruf, der den Onion-Service mit `authorized_clients` startet (C-tor: `ADD_ONION` über den Control-Port; Arti: Start des Onion-Service-Handles) | erster **erfolgreicher** Verbindungsabschluss eines autorisierten Testclients aus einer **getrennten** Tor-Instanz, also der Stopp-Punkt von `T_conn` |
| `T_conn` | Absetzen des SOCKS-`CONNECT` auf die Onion-Adresse durch einen Client, dessen Tor bereits auf Bootstrap 100 % steht | SOCKS-Erfolg **und** erste Anwendungsbytes vom Dienst angenommen |

Randbedingungen, ohne die die Zahlen nicht vergleichbar sind:
- Der Bootstrap des Clients zählt **nicht** zu `T_conn`; er wird getrennt
  protokolliert.
- Der Descriptor-Cache des Clients ist vor jedem `T_conn`-Versuch für diese
  Adresse geleert. Warme Caches messen den Cache, nicht den Aufbau.
- Selbstauskünfte des lokalen Stacks (`HS_DESC UPLOADED` o. ä.) werden
  mitgeschrieben, tragen aber kein Kriterium: `T_pub` endet erst, wenn ein
  **fremder** Client tatsächlich verbindet.
- Abbruch nach 180 s zählt als Fehlversuch und geht als Wert oberhalb der
  Schranke in die Verteilung ein; Fehlversuche werden nicht verworfen.
- n ≥ 100 Verbindungsversuche je Plattformpaar, über ≥ 24 h verteilt, sonst
  ist p95 nicht belastbar.
- Das Messwerkzeug protokolliert Zeitstempel und Lauf-ID, **nie** Onion-Adressen
  oder Credentials (`CLAUDE.md`, Logregel), und erzeugt keinen Verkehr außerhalb
  von Tor.

**Fallback-Kaskade:** Arti → C-tor sandboxed → *(Notfall)* Start ohne Client-Auth ist **kein** akzeptabler Fallback; stattdessen Projektstart verschieben.

**Entscheidung:** Tor-Stack für Phase 1 festgelegt, Migrationspfad dokumentiert.

---

### S2 — Multi-Device-Ratchet-Sync

**Frage:** Funktioniert paarweiser Double-Ratchet-Sync zwischen eigenen Geräten robust, oder braucht es ein Primärgerät-Modell?

**Warum kritisch:** Seit Wegfall der Mailbox trägt Multi-Device die asynchrone Zustellung. Fehler führen zu **Nachrichtenverlust oder Doppelentschlüsselung** — die schlimmste Fehlerklasse.

**Methode:**
1. Simulation: 2–3 Geräte, Kontakt sendet 1000 Nachrichten in zufälliger Reihenfolge
2. Szenarien: gleichzeitiger Empfang, Gerät wochenlang offline, Netztrennung mitten im Ratchet, Uhr-Drift
3. Prüfen: kein Verlust, keine Duplikate, konvergenter Zustand, `skipped_message_keys` bleibt beschränkt
4. Variante B: Primärgerät hält kanonischen Zustand, Zweitgeräte als Replikate mit Send-Proxy

**Erfolgskriterien:**
- 0 Nachrichtenverluste, 0 Duplikate in 10.000 randomisierten Läufen
- Konvergenz < 60 s ab Erreichbarkeit eines datenhaltenden Geschwistergeräts (ADR-07)
- `skipped_message_keys` < 1000 pro Session (Speicherobergrenze)

**Fallback — gezogen:** Das Primärgerät-Modell war als Fallback vorgesehen und ist nach Durchführung des Spikes die **getroffene Entscheidung** (GATE-2 / ADR-17). Preis: Zweitgerät ohne Primärgerät nur eingeschränkt sendefähig.

**Entscheidung:** Multi-Device-Architektur für Phase 2 festgelegt — Primärgerät-Modell, siehe ADR-17 und `spec/protokoll-spec.md` §9.3.

---

### S5 — Akkuverbrauch

**Frage:** Ist Dauererreichbarkeit (Onion-Service + Snowflake + Mesh-Beacons) auf einem Mobilgerät praktikabel?

**Warum kritisch:** Wenn die App den Akku halbiert, wird sie deinstalliert oder der Foreground-Service abgeschaltet — beides zerstört das Zustellmodell **und** verkleinert das Anonymitätsset.

**Methode:**
1. Referenzgeräte (Mittelklasse Android, 3–4 Jahre alt) mit Foreground-Service über 24 h
2. Messreihen: nur Onion · +Snowflake · +Traffic-Shaping · +BLE-Beacons (30 s Intervall)
3. Vergleich gegen Baseline (Gerät idle) und gegen Referenz-Messenger

**Erfolgskriterien:**
- Zusatzverbrauch des Netzprofils ohne Mesh **(R3 − R0) < 8 %/24 h** im
  Leerlauf-Betrieb (kriterientragend, Lesart A1 in `spikes/S5/MESSPROTOKOLL.md` §2)
- BLE-Beacons **(R4 − R3) < 2 %/24 h** zusätzlich; Gesamtbudget mit Mesh damit
  ≤ 10 %/24 h
- (R4 − R0) wird berichtet, trägt aber kein Kriterium
- Kein Thermal-Throttling

**Bezugsgröße und Messprofil (verbindlich, Entscheidung 2026-09-02):**
- Mesh ist Phase 4 und pro Kontakt schaltbar (`gesamtkonzept.md` §2.8). Der
  Tor-Pfad muss die 8 % deshalb **allein** einhalten; „zusätzlich" im
  BLE-Kriterium ist additiv zu lesen.
- **Referenzprofil P-REF (kriterientragend):** 5 Kompartimente (oberes Ende des
  Richtwerts aus `gesamtkonzept.md` §2.2), 5 Kontakte, je Kompartiment
  mindestens einer, davon 1 dauerhaft erreichbar, 0 Nachrichten in der
  Warteschlange, 0 Gruppen. Gemessen wird am oberen Ende des Richtwerts, weil
  sonst genau die Nutzer aus dem Kriterium fallen, die am stärksten
  kompartimentieren.
- **Skalierungslauf P-SKAL (berichtspflichtig, nicht kriterientragend):** R1 und
  R4 je einmal 24 h mit 20 Kontakten in denselben 5 Kompartimenten, um die
  Steigung je Kontakt zu beziffern (Sync-Fenster §10, Beacon-Tokens §13).
  Bricht die Extrapolation auf P-SKAL die 8 %, legt GATE-3 die Parameter oder
  eine dokumentierte Kontaktobergrenze fest.
- Jedes Ergebnis gilt nur für das mitberichtete Profil.
- Die Fallback-Kaskade darf **nicht** am Traffic-Shaping ansetzen, ohne dass
  GATE-3 die Änderung als ADR mit Threat-Model-Abschnitt festhält: Shaping trägt
  G2/G3 (`threat-model.md` §4).

**Fallback-Kaskade:** Shaping-Budget reduzieren → Beacon-Intervall auf 60–120 s → adaptives Verhalten bei Akkustand < 20 % (**Achtung:** darf kein unterscheidbares Netzprofil erzeugen — Anpassung nur bei Mesh, nicht beim Tor-Profil).

**Entscheidung:** Parameter des einheitlichen Netzprofils final festgelegt.

---

## 3. Weitere Spikes — Kurzform

| ID | Erfolgskriterium | Fallback |
|---|---|---|
| **S3** | Revocation → Verbindungsverlust des Revozierten in < 5 min (p95); Intro-Point-Rotation greift | Nutzer sichtbar warnen: „Trennung wird binnen X Minuten wirksam" |
| **S4** | Publikations-Timing korreliert nicht erkennbar mit Geräte-Aufwachzeiten (Klassifikator < 60 % Trefferquote) | Publikations-Jitter erhöhen; ggf. Publikation entkoppeln |
| **S6** | Vollständige Invitation inkl. PQ-Prekeys als QR ≤ Version 20 scanbar | PQ-Prekeys nachgelagert über den 1:1-Kanal statt in der Invitation |
| **S7** | Identische CBOR-Bytes über Rust/Dart/4 Plattformen für 500 Testvektoren | Eigener minimaler Serializer statt Bibliothek |
| **G1** | `openmls` ohne Delivery Service betreibbar; Commit/Welcome/Remove funktional | Gruppen in Phase 1 **weglassen**; Pairwise-Modus zuerst |
| **G2** | Fan-out an 30 Mitglieder < 30 s (p95) über Tor | Gruppengrößen-Limit senken (z. B. 20) |
| **G3** | Mitglied nach 30 Tagen offline kann aufholen oder wird sauber als „muss neu eingeladen werden" markiert | Retention auf 2 Epochen, danach expliziter Re-Add |
| **G4** | Quorum-Schwelle gefunden, bei der Removals < 10 min wirksam sind ohne Gruppenblockade | Schwelle konservativ (z. B. 50 %), UI-Transparenz |
| **G5** | Attestation-Verkehr bei 50 Mitgliedern < 5 % des Gesamtvolumens | Attestations aggregieren/stichprobenartig |
| **E1** | FFI-Durchsatz > 10 MB/s; kein Speicherwachstum über 1 h Dauerlast | Anzeige-Daten seitenweise statt vollständig über die Grenze |
| **E2** | DEK-Schutz auf allen 4 Plattformen funktional; Wipe testbar | Linux ohne TPM: passphrasen-basiert mit klarer UI-Kennzeichnung |
| **E3** | Zwei unabhängige Builder erzeugen bitidentische Artefakte auf allen Plattformen | Zunächst nur Android + Linux reproduzierbar, Rest nachziehen |

---

## 4. Entscheidungs-Gates

Am Ende von Phase 0 werden folgende Entscheidungen **schriftlich fixiert** (als ADR):

| Gate | Entscheidung | Input |
|---|---|---|
| **GATE-1** | Tor-Stack (Arti oder C-tor sandboxed) | S1 |
| **GATE-2** | Multi-Device-Architektur (paarweiser DR oder Primärgerät) | S2 |
| **GATE-3** | Parameter des einheitlichen Netzprofils (Shaping, Intervalle) | S4, S5 |
| **GATE-4** | Gruppen in Phase 1 oder verschoben | G1, G2 |
| **GATE-5** | Zielplattformen für 1.0 (iOS ja/nein) | S5, E1, E2 |
| **GATE-6** | Wire-Format final (CBOR-Profil) | S7 |

**Abbruchkriterium:** Scheitert S1 vollständig (kein Client-Auth auf keiner Plattform), ist das Sicherheitsversprechen nicht haltbar. Dann: Projektpause und Neubewertung — **nicht** ein abgeschwächtes Design.

---

## 5. Weitere Phase-0-Ergebnisse (kein Spike, aber Voraussetzung)

| # | Ergebnis | Verantwortung |
|---|---|---|
| P0-1 | Krypto-Whitepaper (öffentliche Fassung) veröffentlicht | Krypto |
| P0-2 | Threat Model veröffentlicht | Security |
| P0-3 | CI-Pipeline inkl. reproduzierbarer Builds, `cargo-deny`, `cargo-vet` | Infra |
| P0-4 | Binary-Transparency-Log aufgesetzt, Witnesses angefragt | Infra |
| P0-5 | m-of-n-Signierer benannt, Schlüssel in ≥ 3 Jurisdiktionen erzeugt | Projektleitung |
| P0-6 | Design System (Farben, Typo, Komponenten, Assurance-Sprache) | Design |
| P0-7 | Repo-Struktur & Coding-Standards etabliert | Alle |
| P0-8 | Externer Auditor für Phase-5-Audit vorab kontaktiert | Projektleitung |

---

## 6. Risikoregister

| # | Risiko | W | A | Maßnahme | Frühindikator |
|---|---|---|---|---|---|
| R-1 | Arti-Client-Auth nicht produktionsreif | mittel | hoch | C-tor sandboxed als Interim; früher Spike S1 | S1-Zwischenstand Woche 2 |
| R-2 | Akkuverbrauch inakzeptabel | mittel | **sehr hoch** | Parameter-Tuning; Mesh-Intervalle; ehrliche Kommunikation | S5-Erstmessung Woche 3 |
| R-3 | Multi-Device-Sync fehlerhaft → Nachrichtenverlust | mittel | **sehr hoch** | Fallback Primärgerät-Modell; 10.000-Lauf-Testsuite | S2-Fehlerrate Woche 4 |
| R-4 | Kleines Anonymitätsset bei Launch | **hoch** | hoch | Uniformität; Mitschwimmen; Wachstum als Sicherheitsziel; ehrliche Doku | dauerhaft |
| R-5 | `openmls` ungeeignet für serverlosen Betrieb | mittel | mittel | Gruppen verschieben; Pairwise zuerst | G1 Woche 5 |
| R-6 | Reproducible Builds auf iOS/Windows unpraktikabel | mittel | mittel | Zuerst Android/Linux; Rest nachziehen | E3 Woche 6 |
| R-7 | Tor-Blockade in Zielregionen | hoch | mittel | Snowflake/meek; Bridges; Mesh | Feldtests Phase 3 |
| R-8 | Kompartiment-Konzept überfordert Nutzer | mittel | mittel | Usability-Tests früh; sinnvoller Default statt Zwang | Design-Tests Phase 1 |
| R-9 | Zwang gegen Signierer | niedrig | **sehr hoch** | m-of-n über Jurisdiktionen; Binary Transparency | — |
| R-10 | Schlüsselpersonen-Abhängigkeit im Team | mittel | hoch | Pair-Reviews, dokumentierte Entscheidungen (ADRs) | — |

*W = Wahrscheinlichkeit, A = Auswirkung*

---

## 7. Definition of Done für Phase 0

Phase 0 ist abgeschlossen, wenn:

- [ ] Alle 🔴-kritischen Spikes (S1, S2, S5) abgeschlossen und entschieden
- [ ] GATE-1 bis GATE-6 als ADR schriftlich fixiert
- [ ] CI-Pipeline grün, reproduzierbarer Build auf mindestens 2 Plattformen bitidentisch
- [ ] Threat Model und Krypto-Whitepaper veröffentlicht
- [ ] m-of-n-Signierschlüssel erzeugt und verteilt
- [ ] Repo-Struktur, Coding-Standards, Review-Prozess etabliert
- [ ] Risikoregister aktualisiert, keine offenen 🔴 ohne Maßnahme
- [ ] Phase-1-Backlog verfeinert und geschätzt

**Danach ist der Entwicklungsstart von Phase 1 der nächste Schritt.**
