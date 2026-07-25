# Vault Messenger — Engineering-Setup & MVP-Definition

**Letztes Dokument vor Entwicklungsstart.** Fixiert Technologieentscheidungen, Repo-Struktur, Qualitäts-Gates, MVP-Schnitt und Sprint 0.

---

# 1. Architecture Decision Records (ADR)

Verbindlich. Änderung nur durch neuen ADR mit Begründung.

| ID | Entscheidung | Begründung | Konsequenz |
|---|---|---|---|
| **ADR-01** | **Rust-Core + Flutter-UI** | Eine auditierbare, memory-safe Codebasis für alles Sicherheitskritische; eine UI für 4 Plattformen | FFI-Grenze braucht Sorgfalt (Spike E1) |
| **ADR-02** | **Tor als einziger Internet-Transport** | Löst NAT-Traversal, Rendezvous ohne Verzeichnis und beidseitige IP-Anonymität zugleich | Latenz und Akku sind der Preis; kein Direktmodus |
| **ADR-03** | **Onion-Kompartimente mit Per-Kontakt-Client-Auth** | Verhindert HSDir-Enumeration und Präsenz-Probing; granulare Revocation ohne Neu-Verifikation | Kontakte im selben Kompartiment sind untereinander linkbar |
| **ADR-04** | **Invitation-only Identität, kein Verzeichnis, keine Usernamen** | Eliminiert Sybil/Eclipse/Namens-MITM strukturell statt sie zu mildern | Keine Suchbarkeit; Kontakt nur out-of-band |
| **ADR-05** | **PQXDH + Double Ratchet** | Etablierter Standard, PQ-hybrid gegen „harvest now, decrypt later" | Keine Eigenentwicklung erlaubt |
| **ADR-06** | **MLS + Peer-Sequencer für Gruppen; Pairwise-Fanout für Hochrisiko** | MLS braucht lineare Epochen; Sequencer liefert Ordnung, nicht Vertrauen | Sequencer sieht Epochen-Timing; Pairwise skaliert nicht |
| **ADR-07** | **Keine Mailbox: Sender-Queue + Multi-Device + Sync-Fenster** | Entfernt das letzte ortsgebundene Element und dessen Haushalts-Leak | Zustellung nur bei Online-Überlappung |
| **ADR-08** | **SQLCipher + DEK im Plattform-Keystore, Crypto-Erase** | Garantiertes Löschen unabhängig von Flash-Wear-Leveling | Linux ohne TPM benötigt Sonderweg |
| **ADR-09** | **Einheitliches, nicht konfigurierbares Netzprofil** | Jede Option partitioniert das Anonymitätsset und macht Vorsichtige unterscheidbar | Keine „Sicherheitsstufen" im UI |
| **ADR-10** | **m-of-n-Release-Signatur + erzwungene Binary Transparency** | Einziger wirksamer Schutz gegen gezielt manipulierte Builds | Release-Prozess wird aufwendiger |
| **ADR-11** | **Deterministisches CBOR als Wire-Format** | Signaturkonsistenz über Plattformen; kompakt | Serializer-Determinismus muss getestet werden (S7) |
| **ADR-12** | **Android + Desktop zuerst, iOS reduziert** | iOS kann ohne Server keine Instant-Zustellung leisten | iOS-Nutzer bekommen ehrlich kommunizierte Einschränkung |
| **ADR-13** | **Selbstlöschende Nachrichten als Default** | Begrenzt den Schaden durch später übernommene Kontakte | Nutzer können verlängern, nicht global abschalten |
| **ADR-14** | **Kein Telemetrie-, Crash- oder Analytics-Backend** | Jede Rückmeldung wäre ein Metadatenkanal | Fehlerdiagnose nur über freiwillige, lokale Logs |

---

# 2. Repository-Struktur

```
vault/
├─ core/                        # Rust-Workspace
│  ├─ vault-crypto/             # PQXDH, Double Ratchet, AEAD, KDF — keine I/O
│  ├─ vault-identity/           # IK, Kompartimente, Credentials, Geräteliste
│  ├─ vault-wire/               # CBOR-Typen, deterministische Kodierung
│  ├─ vault-transport/          # Trait + tor/, mesh/ Implementierungen
│  ├─ vault-delivery/           # Queue, Routing, ACK-FSM, Sync-Fenster
│  ├─ vault-groups/             # MLS-Wrapper, Sequencer, Attestation, Pairwise
│  ├─ vault-storage/            # SQLCipher, Migrationen, Keystore-Adapter
│  ├─ vault-core/               # Orchestrierung, öffentliche API
│  └─ vault-ffi/                # flutter_rust_bridge-Grenze
├─ app/                         # Flutter
│  ├─ lib/features/             # onboarding, contacts, chat, groups, security
│  ├─ lib/design/               # Design-System-Tokens & Komponenten
│  └─ platform/                 # Foreground-Service, Tray, Keystore-Bridges
├─ spec/                        # Konzept, Protokoll-, Gruppen-Spec, Threat Model
├─ adr/                         # Architecture Decision Records
├─ ops/
│  ├─ reproducible/             # Build-Container, Verifikationsskripte
│  ├─ transparency/             # Binary-Transparency-Log-Tooling
│  └─ signing/                  # m-of-n-Signierprozess
└─ tests/
   ├─ vectors/                  # Krypto-Testvektoren
   ├─ protocol/                 # Modellbasierte Protokolltests
   ├─ fuzz/                     # Fuzz-Targets
   └─ traffic/                  # Metadaten-/Fingerprint-Analyse
```

**Schichtregel (CI-geprüft):** `vault-crypto` hat **keine** I/O- und keine Netzabhängigkeiten. `vault-transport` kennt keine Klartext-Payloads. Verstöße brechen den Build.

---

# 3. Engineering-Praktiken

## 3.1 Sicherheitsregeln im Code

- **`#![forbid(unsafe_code)]`** in allen Crates außer `vault-ffi` und Transport-Bindings; dort `unsafe` nur mit dokumentiertem Review durch zwei Personen
- **`zeroize`** für alle Schlüsselmaterialien; `Drop`-Implementierungen verpflichtend
- Keine Schlüssel, IDs, Onion-Adressen oder Klartexte in Logs — CI-Regel gegen `println!`/`log::` in Krypto-Crates
- Konstantzeit-Vergleiche für alle Geheimnisse (`subtle`)
- Keine `unwrap()`/`expect()` in Bibliothekscode; Fehler explizit typisiert
- Fehlermeldungen dürfen keine Rückschlüsse auf Schlüsselmaterial oder Kontaktexistenz erlauben

## 3.2 Testpflichten

| Ebene | Anforderung |
|---|---|
| Krypto | Bekannte Testvektoren + Property-Tests; Differential-Test gegen Referenzimplementierung |
| Protokoll | Modellbasierte Tests der FSMs (Contact, Delivery, Group) |
| Wire | Roundtrip- und Determinismus-Tests über alle Plattformen |
| Fuzzing | Dauerhafte Fuzz-Targets: `Invitation`, `Envelope`, `GroupFrame`, `Attestation` |
| Multi-Device | Randomisierte 10.000-Lauf-Suite (aus Spike S2) als Regressionstest |
| Traffic | Automatisierte Fingerprint-Analyse: Klassifikator darf App-Traffic nicht > 60 % erkennen |

## 3.3 Review-Prozess

- Jede Änderung an `vault-crypto`, `vault-identity`, `vault-transport`: **Zwei-Personen-Review**, davon eine mit Krypto-Verantwortung
- Änderungen mit Sicherheitsrelevanz erfordern einen Verweis auf Spec-Abschnitt oder ADR
- Abweichung von der Spec ohne ADR = Blocker

---

# 4. CI/CD-Gates

Jeder Merge nach `main` muss passieren:

| Gate | Prüfung |
|---|---|
| G-1 | Build auf allen Zielplattformen |
| G-2 | Tests grün inkl. Krypto-Vektoren und FSM-Modelltests |
| G-3 | `cargo-deny` (Lizenzen, Advisories, Duplikate) |
| G-4 | `cargo-vet` — alle Dependencies geprüft oder freigegeben |
| G-5 | Schichtregel-Check (§2) |
| G-6 | Kein `unsafe` außerhalb Whitelist |
| G-7 | Secret-Scanning + Log-Leak-Regel |
| G-8 | Fuzzing-Smoke (kurze Läufe; lange Läufe nightly) |
| G-9 | **Reproduzierbarer Build:** zwei unabhängige Builder, bitidentisch |
| G-10 | Release zusätzlich: m-of-n-Signaturen vollständig + Eintrag im Binary-Transparency-Log |

---

# 5. MVP-Definition (Phase 1)

**Ziel:** Ein Mensch kann einem anderen über Tor eine Nachricht schicken, die niemand mitlesen und niemand zuordnen kann — auf Android und Desktop.

## 5.1 Im Umfang

- Identitätserzeugung mit Entropie-Gate (ID-1, ID-2)
- Onion-Kompartimente mit Per-Kontakt-Client-Auth (ID-3)
- Invitation per QR und Link, einmalig und replay-fest (CT-1)
- Assurance-Anzeige 🟢/🔵/⚪ (CT-3)
- PQXDH + Double Ratchet, 1:1-Textnachrichten (CR-1, CR-2, MS-1)
- Tor-Transport mit Pflicht-Client-Auth (TR-1)
- Einheitliches Netzprofil (TR-5)
- Persistente Sendequeue + E2E-ACK + ehrlicher Status (DL-1, DL-5)
- Dauererreichbarkeit: Android Foreground-Service, Desktop-Tray (DL-6)
- SQLCipher + Keystore + App-Passcode (SE-1, SE-2, SE-3)
- CI-Gates, reproduzierbare Builds, Signierprozess (SC-1 … SC-5)

## 5.2 Bewusst außerhalb

Anhänge · Gruppen · Mesh · Multi-Device · Snowflake/meek (Phase 3) · Traffic-Shaping (Phase 3) · SMP-Verifikation (Phase 3, im MVP nur QR) · iOS · Sprachnachrichten · Anrufe

## 5.3 Abnahmekriterien

- [ ] Zwei Geräte tauschen Nachrichten ausschließlich über Tor aus; kein Direktverkehr im Mitschnitt nachweisbar
- [ ] Ein nicht autorisierter Client kann den Descriptor **nicht** abrufen (verifiziert per eigenem HSDir-Beobachter)
- [ ] Revocation trennt einen Kontakt innerhalb der in S3 gemessenen Zeit
- [ ] Zustellstatus zeigt nie „zugestellt" ohne empfangenes E2E-ACK
- [ ] Datenbank ist ohne Keystore-Zugriff nicht lesbar; Crypto-Erase getestet
- [ ] Reproduzierbarer Build durch zwei unabhängige Builder bitidentisch
- [ ] Keine Netzwerkverbindung außer Tor (verifiziert per Firewall-Test)

---

# 6. Sprint 0 (erste zwei Wochen nach Phase 0)

| # | Aufgabe |
|---|---|
| 1 | Repo-Skelett gemäß §2, Workspace, Schichtregel-Check in CI |
| 2 | CI-Pipeline mit G-1 … G-8 |
| 3 | `vault-wire`: CBOR-Typen für Invitation und Envelope + Determinismus-Tests |
| 4 | `vault-crypto`: PQXDH-Skelett mit Testvektoren |
| 5 | `vault-transport/tor`: Onion-Service hochfahren, Client-Auth setzen (Ergebnis aus GATE-1) |
| 6 | Flutter-Skelett + FFI-Grenze mit einem Ende-zu-Ende-Durchstich („Hello" über Tor) |
| 7 | Design-System-Tokens in `app/lib/design` |
| 8 | Testharness für zwei Instanzen auf einer Maschine |

**Sprint-0-Ziel:** Ein Durchstich — zwei lokale Instanzen tauschen eine unverschlüsselte Testnachricht über zwei echte Onion-Services mit Client-Auth aus. Damit ist die riskanteste Integration bewiesen.

---

# 7. Startfreigabe-Checkliste

Entwicklungsstart Phase 1 ist freigegeben, wenn:

- [ ] Phase-0-Spikes S1, S2, S5 abgeschlossen (🔴-kritisch)
- [ ] GATE-1 bis GATE-6 als ADR fixiert
- [ ] Risikoregister ohne offene 🔴 ohne Maßnahme
- [ ] Repo-Struktur und CI-Gates stehen
- [ ] Threat Model und Krypto-Whitepaper veröffentlicht
- [ ] m-of-n-Signierschlüssel in ≥ 3 Jurisdiktionen erzeugt
- [ ] MVP-Backlog geschätzt, Sprint 0 geplant
- [ ] Externer Auditor für Phase 5 vorab kontaktiert

---

# 8. Dokumentenlandkarte

| Dokument | Zweck |
|---|---|
| **Gesamtkonzept** | Verbindliche Architektur, Prioritäten, verworfene Ansätze (Anhang A) |
| **Protokoll-Spezifikation** | Formate, Handshake, Zustellung, Revocation, Mesh |
| **Gruppen-Spezifikation** | MLS-Modus, Sequencer, Attestation, Pairwise-Modus |
| **Threat Model** | Angreiferklassen × Assets × Maßnahmen × Restrisiken |
| **Phase-0-Arbeitspaket** | Spikes, Gates, Risikoregister |
| **Engineering-Setup** *(dieses)* | ADRs, Repo, CI, MVP, Sprint 0 |

Alle sechs bilden zusammen die vollständige Grundlage. Änderungen laufen über ADRs; die Specs sind die normative Referenz für die Implementierung.
