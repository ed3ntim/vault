# Vault Messenger — Formales Threat Model

**Grundlagendokument für Audit, Implementierung und externe Prüfung.**
Bezugsdokumente: Gesamtkonzept, Protokoll-Spezifikation, Gruppen-Spezifikation.

---

## 1. Systemgrenzen und Vertrauensannahmen

### 1.1 Vertrauensgrenzen

```
┌─ VERTRAUT ──────────────────────────────────────────┐
│  Endgerät des Nutzers (Annahme, siehe 1.3)          │
│  Plattform-Keystore (Secure Enclave / TPM / StrongBox)│
│  Lokale App-Instanz + Rust Core                      │
└──────────────────────────────────────────────────────┘
        │ Vertrauensgrenze
┌─ NICHT VERTRAUT ─────────────────────────────────────┐
│  Tor-Netz (Relays, HSDirs, Guards, Bridges)          │
│  Jedes Netzsegment zwischen Nutzern                  │
│  Jeder Kontakt (kann übernommen/gezwungen werden)    │
│  Jedes Gruppenmitglied                               │
│  App-Stores, Betriebssystem-Update-Kanäle            │
│  Physische Funkumgebung (BLE/Wi-Fi)                  │
└──────────────────────────────────────────────────────┘
```

**Es gibt keine vertraute Infrastruktur.** Das System besitzt keinen Server, keinen Betreiber, keinen Verzeichnisdienst und keinen privilegierten Knoten. Das Tor-Netz wird als potenziell teilweise gegnerisch modelliert.

### 1.2 Sicherheitsannahmen (falsifizierbar)

| # | Annahme | Falls verletzt |
|---|---|---|
| SA-1 | Ed25519, X25519, ML-KEM-768, XChaCha20-Poly1305, BLAKE3 sind sicher | Totalverlust der Vertraulichkeit |
| SA-2 | Der Gegner kontrolliert **nicht** alle Tor-Relays gleichzeitig | Deanonymisierung möglich |
| SA-3 | Der Plattform-Keystore schützt den DEK gegen Auslesen durch Apps | Lokale Daten lesbar |
| SA-4 | Der Nutzer verifiziert mindestens per SMP, idealerweise per QR | MITM beim Erstkontakt möglich |
| SA-5 | Mindestens `m` von `n` Release-Signierern sind nicht gleichzeitig gezwungen | Manipulierter Build auslieferbar |
| SA-6 | Das Endgerät ist nicht kompromittiert | Alle Schutzmaßnahmen wirkungslos |

### 1.3 Explizit außerhalb des Scopes

Per Vorgabe in Nutzerverantwortung, durch App-Passcode adressiert:

- Verlust, Diebstahl, Beschlagnahme des Geräts
- Tastaturen/IMEs, Zwischenablage-Manager, Accessibility-Dienste, die Eingaben exfiltrieren
- Endpoint-Kompromittierung durch Malware oder staatlichen Implant
- Erzwungene Herausgabe des App-Passcodes durch den Nutzer selbst
- Screen-Recording, Schulterblick, physische Beobachtung

---

## 2. Angreiferklassen

| ID | Klasse | Fähigkeiten |
|---|---|---|
| **A1** | Globaler passiver Beobachter (SIGINT) | Sicht auf große Teile des Internetverkehrs, Langzeitspeicherung, statistische Korrelation über Monate |
| **A2** | Lokaler Netzbeobachter / ISP | DPI, Verkehrsmuster, Blockierung, Sicht auf eine Leitung/Region, staatlich weisungsgebunden |
| **A3** | Tor-Infrastruktur-Angreifer | Betreibt Relays, Guards, HSDirs, Bridges; Sybil im Tor-Netz |
| **A4** | Übernommener Kontakt (Insider) | Vollzugriff auf eine bestehende Beziehung: Klartext, Identität, Timing; wurde gezwungen oder ist Agent |
| **A5** | Physisch naher Angreifer | BLE/Wi-Fi-Sniffing, Funkpeilung, IMSI-Catcher, Anwesenheit am selben Ort |
| **A6** | Lieferketten-/Zwangsangreifer | Rechtlicher Zwang gegen Entwickler, Signaturschlüssel, App-Stores; Dependency-Kompromittierung |
| **A7** | Aktiver Netzangreifer | MITM-Versuche, Injection, Replay, gezielte Verfügbarkeitsangriffe |
| **A8** | Geräte-Angreifer | *Out of Scope (§1.3)* |

---

## 3. Schutzgüter

| ID | Asset | Warum kritisch |
|---|---|---|
| **G1** | Nachrichteninhalte | Offensichtlich |
| **G2** | Kommunikationsgraph (wer mit wem) | Für Nachrichtendienste oft wertvoller als Inhalte |
| **G3** | Präsenz-/Aktivitätsmuster (Pattern of Life) | Ermöglicht Verhaltensprofile, Aufenthaltsschlüsse |
| **G4** | Verknüpfung Pseudonym ↔ reale Person | Deanonymisierung = Ende jedes Schutzes |
| **G5** | Tatsache der Nutzung (Detection of Use) | In vielen Jurisdiktionen bereits belastend |
| **G6** | Gruppenmitgliedschaft | Deckt Organisationsstrukturen auf |
| **G7** | Standort | Physische Gefährdung |
| **G8** | Verfügbarkeit / Zustellbarkeit | Stiller Verlust ist gefährlicher als Mitlesen |
| **G9** | Software-Integrität | Bricht alles andere auf einen Schlag |

---

## 4. Bedrohungsmatrix

Legende Restrisiko: **○** vernachlässigbar · **◐** gemindert, benannt · **●** offen, prinzipiell hart

### A1 — Globaler passiver Beobachter

| Asset | Angriff | Gegenmaßnahme | Rest |
|---|---|---|---|
| G1 | Mitschnitt und spätere Entschlüsselung | E2E mit PQXDH (PQ-hybrid) + Double Ratchet; Forward Secrecy pro Nachricht | ○ |
| G2 | Ende-zu-Ende-Timing-Korrelation über Tor | Onion-Services (keine direkte IP-Beziehung), Padding auf Größenklassen, Alltags-Traffic-Shaping, Vanguards | ◐ |
| G2/G3 | Intersection-/Statistical-Disclosure über Monate | Sync-Fenster pro Paar verschieden, session-gebundenes Shaping, randomisierte Descriptor-Publikation | ● |
| G4 | Traffic-Confirmation Guard↔Ziel | Vanguards-lite (L2/L3-Pinning), Tor-Standard-Guard-Policy | ◐ |
| G5 | Erkennung anhand Protokoll-Fingerprint | Snowflake/meek als Standard → Mitschwimmen im generischen WebRTC/HTTPS-Aufkommen | ◐ |

### A2 — Lokaler Netzbeobachter / ISP

| Asset | Angriff | Gegenmaßnahme | Rest |
|---|---|---|---|
| G5 | „Diese Person nutzt ein Anonymitätswerkzeug" | Getarnte Transporte ab der ersten Verbindung; **kein** Constant-Rate-Muster (bewusst verworfen); einheitliches Netzprofil für alle | ◐ |
| G3 | Online-Zeiten aus Verbindungsaufkommen | Session-gebundenes Shaping, gestreute Publikationszeitpunkte | ◐ |
| G8 | Blockade des Zugangs | obfs4, Snowflake, meek, nicht-gelistete Bridges; Mesh als Ausweichweg | ● |
| G5 | Korrelation des Erst-Bootstraps (Installationszeitpunkt) | Getarnte Transporte von Beginn an, gestreute Erstpublikation, Bridge-Bezug out-of-band mit der Invitation | ◐ |

### A3 — Tor-Infrastruktur-Angreifer

| Asset | Angriff | Gegenmaßnahme | Rest |
|---|---|---|---|
| G2/G6 | HSDir-Enumeration: welche Dienste existieren | **Tor v3 Client Authorization (Pflicht)** — Descriptor ist an Kontakt-Schlüssel verschlüsselt; Existenz nicht bestätigbar | ○ |
| G3 | Präsenz-Probing durch Fremde | Client-Auth verhindert Descriptor-Abruf und damit jedes Proben durch Nicht-Kontakte | ○ |
| G2 | Rückschluss auf Kontaktanzahl aus Descriptor-Volumen | **Kompartimente statt Per-Kontakt-Onions** (wenige Dienste, Per-Kontakt-Credentials) | ○ |
| G4 | Guard-Discovery gegen einen Onion-Service | Vanguards-lite; Gerät agiert bevorzugt als Client | ◐ |
| G8 | Introduction-Point-Flooding (DoS) | Client-Auth: Fremde können keine Intro-Zellen platzieren | ◐ |

### A4 — Übernommener Kontakt (Insider)

| Asset | Angriff | Gegenmaßnahme | Rest |
|---|---|---|---|
| G1 | Liest alle gemeinsamen Nachrichten | Kryptografisch unlösbar. Begrenzung: selbstlöschende Nachrichten als **Default** | ● |
| G2 | Deckt Teilgraph auf | **Kompartimentierung** — offenbart nur sein Kompartiment, nicht das Gesamtnetz | ◐ |
| G3 | Präsenz-Probing als autorisierter Kontakt | Multi-Device: nur „mindestens ein Gerät erreichbar"; gestreute Publikation; sofortige Einzel-Revocation. Auch das Re-Ack (`protokoll-spec.md` §9.3 Regel 2, ADR-21) ist ein Lebenszeichen; begrenzt durch 5 Re-Acks je Cache-Eintrag und Stunde sowie denselben Ack-Jitter wie reguläre Acks | ◐ |
| G7 | Physisches Tracking über Mesh-Beacons | Mesh-Sichtbarkeit **pro Kontakt schaltbar**; Revocation löscht `mesh_key` → Token nicht mehr berechenbar | ◐ |
| G6 | Gruppenmitgliedschaft und -timing | Inhärent an der Mitgliedschaft. Minimierung: Pairwise-Fanout-Modus ohne Gruppen-Metadatenpunkt | ● |
| G1 | Content-Equivocation in Gruppen | Transcript-Hash-Kette + Gossip → Divergenz wird gemeldet | ◐ |
| — | Weiterbestehender Zugriff nach Enttarnung | **Ein-Schritt-Revocation**: Credential + Intro-Point-Rotation + Mesh-Key + Session-Purge; **erzwungene Intro-Point-Rotation (ADR-15) statt Transport-Garantie** | ◐ (○ erst nach S3-Nachweis, dass die Rotation greift) |

### A5 — Physisch naher Angreifer

| Asset | Angriff | Gegenmaßnahme | Rest |
|---|---|---|---|
| G4/G7 | Wiedererkennung über BLE-Identifier | Rotierende Identifier auf **allen** Ebenen (MAC, Service-ID, Payload), synchron rotiert | ◐ |
| G7 | Replay eines Beacons zur Ortsplatzierung | PSI-Beacon mit **Challenge-Response-Frische**; aufgezeichnete Tokens wertlos | ○ |
| G2 | Erkennen, wer mit wem im Mesh spricht | Tokens nur für echte Kontakte berechenbar; Bloom-Filter; ephemere Transport-Tags | ◐ |
| G8 | Akku-DoS durch Beacon-Flooding | Rate-Limits pro Quelle, konstanter Prüfaufwand statt O(N) | ○ |
| G2 | Verkettung derselben Nachricht über Mesh **und** Tor | **Cross-Transport-Identifier-Isolation**: keine stabilen Tags über Transportgrenzen | ○ |

### A6 — Lieferketten-/Zwangsangreifer

| Asset | Angriff | Gegenmaßnahme | Rest |
|---|---|---|---|
| G9 | Gezielt manipulierter Build für eine Einzelperson | **m-of-n-Schwellwert-Signatur über mehrere Jurisdiktionen** + **erzwungene Binary Transparency** (Client installiert nur log-verifizierte Builds) → gezielte Auslieferung wird öffentlich sichtbar | ◐ |
| G9 | Kompromittierter Signaturschlüssel | Schwellwert-Signatur: ein Schlüssel genügt nicht | ○ |
| G9 | Kompromittierte Dependency | `cargo-vet`/`cargo-crev`, gepinnte & hash-verifizierte Deps, minimale Fläche, zwei unabhängige reproduzierbare Builds als Release-Gate | ◐ |
| G9 | Stiller Auto-Update-Push | **Kein stiller Auto-Update**; lokale Prüfung gegen Log + Schwellwert-Signatur | ○ |
| G5 | Store-Metadaten (wer hat installiert) | F-Droid + signierte Direkt-Binaries als beworbene Alternative | ● |

### A7 — Aktiver Netzangreifer

| Asset | Angriff | Gegenmaßnahme | Rest |
|---|---|---|---|
| G1/G4 | MITM beim Erstkontakt | **Self-certifying Identity** (Adresse = Schlüssel) → Substitution für bekannte Adresse unmöglich; QR bei Treffen; **SMP** für Remote (stimmklonungsfest) | ◐ (SA-4) |
| G1 | Abfangen und Einlösen einer Invitation | Invitation einmalig, kurzlebig, **replay-fest** (`invite_nonce`, genau einmal verbraucht) | ○ |
| G1 | Replay alter Nachrichten | Double-Ratchet-Zählerlogik, AEAD mit Header-AD | ○ |
| G8 | Gezielte Nichtzustellung / stiller Drop | Zustellstatus **nur** über E2E-ACK; `WAITING` statt Falschmeldung; persistente Retry-Queue | ○ |
| G6 | Gruppen-Fork durch bösartigen Sequencer | Sequencer ist **keine Korrektheitskomponente**: deterministische Konfliktauflösung (`argmin H(commit)`) + Attestation-Gossip → Fork unmöglich, nur Verzögerung, diese erkennbar | ◐ |
| G6 | Ghost-Member nach Entfernung | Quittierte Removals mit Quorum; Senden pausiert bis Verteilung bestätigt | ◐ |

---

## 5. Das dominante Restrisiko: Anonymitätsset

**Nicht in der Matrix abbildbar, weil es keine Einzelmaßnahme adressiert.**

Ein Staat muss keine Kryptografie brechen, wenn die Frage „wer nutzt diese App in meinem Land?" bereits eine kleine, handhabbare Zielmenge ergibt. Anonymität ist eine Eigenschaft der Menge, nicht des Protokolls.

**Designkonsequenzen (bereits umgesetzt):**
- Sicherheitsrelevantes Netzverhalten ist **nicht konfigurierbar** — keine Optionen, die Nutzer unterscheidbar machen
- **Keine Sicherheitsstufen** — Vorsicht darf niemanden verraten
- Mitschwimmen im großen Fremdtraffic statt eigener Kohorte
- **Nutzerwachstum ist ein Sicherheitsziel**, nicht nur ein Produktziel

**Bewertung:** Bei kleiner Nutzerbasis bietet das System für Hochrisiko-Ziele in kleinen Jurisdiktionen **keinen ausreichenden Schutz**. Das wird dokumentiert und kommuniziert, nicht wegbeworben.

---

## 6. Zusammenfassung der offenen Restrisiken (●)

| # | Restrisiko | Begründung |
|---|---|---|
| R1 | **Anonymitätsset / Nutzerzahl** | Nicht technisch lösbar (§5) |
| R2 | **Langzeit-Intersection durch A1** | Offenes Forschungsproblem; gilt für jedes existierende System |
| R3 | **Insider-Kontakt liest Inhalte** | Kryptografisch unlösbar; nur zeitlich begrenzbar |
| R4 | **Gruppenmitgliedschaft gegenüber Mitgliedern** | Inhärent; Pairwise-Modus minimiert |
| R5 | **Verfügbarkeit unter Totalzensur** | Pluggable Transports und Mesh mildern, garantieren nichts |
| R6 | **Store-Installationsmetadaten** | Ausweichweg F-Droid/Direktdownload existiert, wird aber nicht von allen genutzt |

Alles Übrige ist auf **○** oder **◐** gemindert oder liegt außerhalb des Scopes (§1.3).

---

## 7. Verifikationsplan (wie wird das geprüft?)

| Bereich | Methode |
|---|---|
| Krypto-Implementierung | Bekannte Testvektoren, Property-Tests, Differential-Tests gegen Referenzimplementierungen |
| Protokoll-Zustandsautomaten | Modellbasierte Tests, Protokoll-Fuzzing (Envelope, Invitation, GroupFrame) |
| Metadaten-Eigenschaften | Traffic-Capture-Analyse im Labor: Größenverteilung, Timing, Fingerprint-Klassifikator gegen eigene Aufzeichnungen |
| Präsenzschutz | Probing-Test durch nicht-autorisierten Client gegen eigene Kompartimente |
| Revocation-Wirksamkeit | Zeitmessung „Revocation → Verbindungsverlust" (Spike S3) |
| Reproduzierbarkeit | Zwei unabhängige Builder, bitidentischer Vergleich als CI-Gate |
| Gesamtdesign | Externes Security-Audit vor 1.0 (Pflicht-Gate) |
