# Vault Messenger — Gesamtkonzept (konsolidiert)

**Stand: Konsolidierung der Iterationen v1–v7 · Single Source of Truth**

Dieses Dokument ersetzt alle vorherigen Fassungen. Überholte Entscheidungen sind entfernt, nicht kommentiert — was hier steht, gilt. Anhang A listet die verworfenen Ansätze mit Begründung, damit sie nicht versehentlich wieder eingeführt werden.

---

# 1. Zielbild & Prioritäten

Ein plattformübergreifender Messenger (Android, Windows, Linux, iOS eingeschränkt), der ohne jede Betreiber-Infrastruktur auskommt und primär gegen staatliche Überwachung ausgelegt ist.

**Verbindlicher Prioritätsstack — löst jeden Zielkonflikt:**

1. **Anonymität & Datenschutz** — höchste Priorität
2. **Serverlosigkeit** — Must-have, kein betreibbares Backend
3. **Alles andere** (Komfort, Latenz, Reichweite von Features) — nachrangig und bewusst opferbar

## 1.1 Bedrohungsmodell

**Primärer Gegner:** Staat / Nachrichtendienst. Fähigkeiten: Sicht auf große Netzabschnitte, Betrieb eigener Tor-Relays und HSDirs, DPI beim ISP, Zwang gegen Unternehmen und Entwickler, Übernahme einzelner Kontakte, physische Nähe (Mesh-Sniffing), Langzeitbeobachtung.

**Explizit im Scope:** Deanonymisierung, Metadatenanalyse, Traffic-Korrelation, Verzeichnis-/Namensangriffe, MITM beim Kontaktaufbau, Lieferkettenangriffe, Zensur, Präsenz- und Nutzungsermittlung.

**Explizit außerhalb des Scopes** (per Vorgabe, Verantwortung des Nutzers):
- Verlust, Diebstahl oder Beschlagnahme des Geräts → abgedeckt durch App-Passcode
- Tastaturen/IMEs, die Eingaben nach Hause telefonieren
- Endpoint-Kompromittierung durch Implant/Malware

## 1.2 Kernversprechen

- Keine Telefonnummer, keine E-Mail, kein Konto, kein Verzeichnis
- Kein Server, der Nachrichten annimmt, weiterleitet, speichert oder Nutzer kennt
- Weder Sender noch Empfänger sehen die IP der Gegenseite
- Kein Netzbeobachter kann feststellen, wer mit wem kommuniziert
- Alle Daten ausschließlich verschlüsselt auf den Geräten des Nutzers

---

# 2. Technisches Konzept

## 2.1 Identität

- Beim Erststart lokal erzeugtes **Ed25519-Identitätspaar**; daraus wird direkt die **Tor-Onion-v3-Adresse** abgeleitet. Zusätzlich ein **X25519-Paar** für den Schlüsselaustausch.
- **Self-certifying:** Adresse und öffentlicher Schlüssel sind identisch. Key-Substitution ist für eine bekannte Adresse strukturell unmöglich — unabhängig davon, wie feindlich das Netz ist.
- **Entropie-Gate:** Schlüsselerzeugung erst nach ausreichender Entropie aus dem Plattform-CSPRNG, nie unmittelbar nach dem Boot.
- Kein Username, keine Auflösung, keine Registrierung. Es gibt nichts, was ein Angreifer abfragen, fälschen oder beschlagnahmen könnte.

## 2.2 Kompartimente & Erreichbarkeit

Statt einer globalen Adresse oder einer Adresse pro Kontakt betreibt jedes Gerät **wenige Onion-Kompartimente** (Richtwert 2–5, nach Kontext getrennt, z. B. privat / beruflich / hochsensibel).

- **Tor v3 Client Authorization ist Pflicht.** Der Descriptor ist an die Schlüssel der berechtigten Kontakte verschlüsselt. Wer keine Credential besitzt, kann den Dienst weder finden noch seine Existenz bestätigen noch ihn proben.
- **Jeder Kontakt erhält eine eigene Client-Auth-Credential** innerhalb seines Kompartiments. Damit ist **granulare Revocation** möglich: Ein feindlich gewordener Kontakt wird einzeln entfernt, alle anderen bleiben unberührt, keine Neu-Verifikation nötig.
- **Wirkung gegen den Staatsgegner:** HSDir-Enumeration läuft ins Leere, netzweites Scannen ist unmöglich, die Kontaktanzahl ist nicht aus dem Descriptor-Volumen ableitbar.
- **Bewusste Restlinkbarkeit:** Kontakte innerhalb eines Kompartiments teilen eine Adresse. Zwei kompromittierte Kontakte im selben Kompartiment wissen, dass sie dieselbe Person kennen. Deshalb Trennung nach Bedrohungskontext; hochsensible Kontakte erhalten ein eigenes, minimal besetztes Kompartiment.

## 2.3 Kontaktaufbau

Ausschließlich out-of-band, ohne jeden Netzabruf und ohne Dritte:

| Weg | Assurance |
|---|---|
| **QR-Code bei persönlichem Treffen** (Goldstandard, im UX stark bevorzugt) | 🟢 verifiziert |
| **NFC / Mesh-Handshake in physischer Nähe** | 🟢 verifiziert |
| **Invitation-Link über bestehenden Kanal + Remote-Verifikation** | 🔵 bestätigt |
| Invitation ohne durchgeführte Verifikation | ⚪ niedrige Assurance, sichtbar markiert |

- Die Invitation enthält Onion-Adresse, Client-Auth-Credential, X25519-Prekey und ein Einmal-Secret. Sie ist **einmalig, kurzlebig und replay-fest** (Nonce) — abgefangene Links sind wertlos.
- **Remote-Verifikation über gemeinsames Vorwissen** (Socialist-Millionaire-Prinzip): Beide belegen ein nur ihnen bekanntes Geheimnis. Das funktioniert auch, wenn ein Sprachkanal vollständig gefälscht ist.
- **SAS-Wortvergleich** bleibt verfügbar, gilt aber nicht mehr als hinreichend: Echtzeit-Stimmklonung macht den Sprachvergleich gegen einen staatlichen MITM unzuverlässig. Die UI weist das aus.

## 2.4 Kryptografie

| Zweck | Verfahren |
|---|---|
| Initialer Schlüsselaustausch | **PQXDH** — X25519 + ML-KEM (Kyber) hybrid, gegen „harvest now, decrypt later" |
| Nachrichten 1:1 | **Double Ratchet** — Forward Secrecy & Post-Compromise Security pro Nachricht |
| Gruppen | **MLS (RFC 9420)** bzw. Pairwise-Fanout (§2.7) |
| Anhänge | **XChaCha20-Poly1305**, Schlüssel in der Nachricht |
| Authentisierung | **Abstreitbare MACs** statt Signaturen, wo möglich → kein kryptografischer Beweis gegenüber Dritten, wer was geschrieben hat |
| Lokale Ablage | **SQLCipher** (AES-256) |

Grundsatz: ausschließlich etablierte Primitive und Bibliotheken, kein Eigenbau.

## 2.5 Transport

**Alles läuft über Tor.** Es gibt keinen Modus, in dem IP-Adressen das Anonymitäts-Overlay verlassen — ein „schneller Direktmodus" existiert bewusst nicht.

- **Onion-Services mit Client-Auth** als Erreichbarkeitsmechanismus (§2.2). Das löst gleichzeitig NAT-Traversal, Rendezvous ohne Verzeichnis und beidseitige IP-Anonymität.
- **Snowflake/meek als Standard-Transport.** Der Verkehr verschwindet im großen, generischen WebRTC/HTTPS-Aufkommen — statt in einer kleinen, app-typischen Kohorte. obfs4 und nicht-gelistete Bridges als Alternativen gegen Blocking.
- **Vanguards-lite** (L2/L3-Guard-Pinning) plus Tor-Standard-Guard-Policy gegen Guard-Discovery.
- **Traffic-Shaping auf ein Alltagsprofil:** Padding auf feste Größenklassen, Sendemuster mit natürlicher Varianz, session-gebunden statt dauerhaft. Ziel ist Unauffälligkeit, nicht mathematische Gleichverteilung.
- **Ein einziges Netzprofil für alle Nutzer** (siehe §2.9).
- **Entschärfter Erst-Bootstrap:** getarnte Transporte von der ersten Verbindung an, gestreute Erstpublikation der Descriptors, Bridge-Bezug out-of-band gemeinsam mit der Invitation.
- **Tor-Stack:** Zielarchitektur **Arti** (Rust, memory-safe). Bis dessen Onion-Client-Auth produktionsreif ist, **C-tor in Prozessisolation mit seccomp-Sandbox**.

## 2.6 Zustellung — ohne jede Infrastruktur

Es gibt keine Mailbox, keinen Relay, keinen Zwischenspeicher. Vier Bausteine:

1. **Persistente Ausgangswarteschlange beim Sender.** Die verschlüsselte Nachricht bleibt beim Sender und wird automatisch zugestellt, sobald der Empfänger erreichbar ist. Kein Dritter hält je etwas.
2. **Multi-Device als natürlicher Puffer.** Handy und PC gehören zum selben Kompartiment und decken zusammen fast den ganzen Tag ab. Der Sender stellt an das gerade erreichbare Gerät zu; die eigenen Geräte synchronisieren den Verlauf später direkt P2P.
3. **Ausgehandelte Sync-Fenster.** Beide Clients leiten aus dem gemeinsamen Kontaktgeheimnis identische Erreichbarkeitszeitpunkte ab. Das erhöht die Überlappung deutlich, ist pro Kontaktpaar verschieden und von außen nicht vorhersagbar.
4. **Mesh bei physischer Nähe** (§2.8) — sofortige Zustellung ohne Internet.

**Voraussetzung für gutes Verhalten:** „Online" muss *Gerät an* bedeuten, nicht *App offen*. Android nutzt dafür einen Foreground-Service, Desktop den Autostart im Tray. Dann fühlt sich die Zustellung im Alltag unmittelbar an, und echte Wartezeiten treten nur bei tatsächlichen Offline-Phasen auf.

**Zustellstatus ist ehrlich:** „zugestellt" wird ausschließlich durch ein **Ende-zu-Ende-ACK des Empfängers** gesetzt. Wartende Nachrichten zeigen „wartet auf Erreichbarkeit" — nie eine Falschmeldung.

## 2.7 Gruppen

- **Standard:** MLS mit einem **Peer-Sequencer** — ein rotierendes Gruppenmitglied ordnet ausschließlich **opake** Handshake-Blobs, um die von MLS benötigte lineare Epochenfolge herzustellen. Es liest nichts.
- **Equivocation-Erkennung:** Mitglieder signieren Hashes der gesehenen Commit-Sequenz und gossippen sie. Ein forkender oder Commits unterschlagender Sequencer wird erkennbar. Membership-Änderungen gelten erst als wirksam, wenn der neue Epochen-Commit quittiert propagiert ist → keine Ghost-Member.
- **Hochsensible Kleingruppen:** **Pairwise-Fanout** — die Gruppe besteht intern aus N paarweisen 1:1-Kanälen, ohne zentralen Gruppen-Metadatenpunkt. Ein staatliches Mitglied sieht nur seine eigenen Beziehungen, nicht den Gruppengraphen.
- **Content-Equivocation-Schutz im Pairwise-Modus:** Jede Nachricht trägt einen Hash über den bisherigen Gruppen-Transcript; die Hashes werden über die paarweisen Kanäle abgeglichen. Sendet ein Mitglied unterschiedliche Inhalte an verschiedene Empfänger, divergieren die Hashes und die App meldet die Inkonsistenz.

## 2.8 Mesh (ohne Internet)

| Kanal | Reichweite | Einsatz |
|---|---|---|
| Wi-Fi Direct / Wi-Fi Aware | ~100 m | Dateien, hoher Durchsatz |
| Bluetooth LE | ~10–50 m | Text, Discovery |
| Lokales LAN (mDNS) | Netzwerk | gleicher Router/Hotspot |

- **Private Contact Discovery:** Beacons enthalten aus dem gemeinsamen Kontaktgeheimnis abgeleitete Tokens mit **Challenge-Response-Frische**. Nur ein echter Kontakt kann sie berechnen; aufgezeichnete Tokens sind nicht wiederverwendbar (kein Replay, keine Ortsplatzierung). Ein Sniffer sieht unverknüpfbares Rauschen.
- **Rotierende Identifier auf jeder Ebene** (MAC, Service-IDs, App-Payloads), synchron rotiert — keine Verkettung über Zeit und Ort.
- **Epidemisches Store-and-forward** nur für Blobs mit gültiger Empfänger-Capability, mit Hop-Limit, TTL und Speicherbudget. Standard: nur für Kontakte weiterleiten.
- **Rate-Limits und konstanter Prüfaufwand** gegen Akku-DoS durch Beacon-Flooding.
- **Mesh-Sichtbarkeit ist pro Kontakt schaltbar** — ein revozierter Kontakt kann nicht mehr physisch tracken.
- **Cross-Transport-Isolation:** Keine stabilen Identifier über Transportgrenzen. Dedup ausschließlich auf der entschlüsselten Innenschicht; jede Transportschicht trägt eine eigene ephemere Umhüllung. Ein Beobachter mit Sicht auf Tor *und* Mesh kann dieselbe Nachricht nicht verketten.

## 2.9 Ununterscheidbarkeit — Anonymitätsset als Designziel

Der wichtigste Befund der Iterationen: **Anonymität ist eine Eigenschaft der Menge.** Ein Staat muss die Krypto nicht brechen, wenn die Frage „wer nutzt das?" bereits eine kleine Zielmenge liefert.

Daraus folgen harte Designregeln:

- **Sicherheitsrelevantes Netzverhalten ist nicht konfigurierbar.** Padding-Klassen, Sendetakt, Transport-Defaults und Rotationsintervalle sind fest. Jede Option, die das Netzverhalten ändert, würde die Nutzerbasis partitionieren und Vorsichtige identifizierbar machen.
- **Es gibt keine Sicherheitsstufen.** Ein Nutzer darf sich nicht durch seine Vorsicht verraten.
- **Mitschwimmen statt Auffallen:** Snowflake/meek als Standard, damit der Verkehr in großem Fremdaufkommen verschwindet.
- **Wachstum ist ein Sicherheitsziel**, nicht nur ein Produktziel.

**Ehrliche Konsequenz:** Solange die Nutzerbasis klein ist, bietet das Tool für Hochrisiko-Ziele in kleinen Jurisdiktionen keinen ausreichenden Schutz. Das wird dokumentiert, nicht wegbeworben.

## 2.10 Lokale Speicherung

- **SQLCipher**-Datenbank; der Data-Encryption-Key liegt im Plattform-Keystore (Secure Enclave, StrongBox, TPM, Secret Service) und ist an App-Passcode/Biometrie gebunden (Argon2id).
- **Sicheres Löschen = Crypto-Erase:** Vernichtung des DEK im Keystore macht alle Daten unabhängig von Flash-Wear-Leveling unwiederbringlich.
- **Selbstlöschende Nachrichten sind Default**, nicht Option. Das begrenzt den Schaden, wenn ein Kontakt später übernommen wird.
- **Keine Cloud-Backups**, Plattform-Auto-Backup explizit deaktiviert. Gerätemigration nur lokal per QR-Handshake.
- Keine Klartext-Inhalte in Benachrichtigungen auf dem Sperrbildschirm.

*Hinweis: Duress-PIN, Decoy-Account und Hidden-Volume-Deniability sind entworfen, aber deprioritisiert (P2), da Gerätebeschlagnahme außerhalb des Scopes liegt.*

## 2.11 Lieferkette

Der effizienteste Staatsangriff ist nicht das Protokoll, sondern der Update-Kanal.

- **m-of-n-Schwellwert-Signatur** über mehrere Jurisdiktionen: Ein Release ist nur gültig, wenn z. B. 3 von 5 organisatorisch und geografisch getrennte Maintainer signieren. Eine einzelne Behörde kann keinen gültigen Build erzwingen.
- **Erzwungene Binary Transparency:** Der Client installiert ausschließlich Builds, die im öffentlichen Append-only-Log stehen und dort von unabhängigen Beobachtern gesehen wurden. Ein gezielt an eine Einzelperson gerichteter Build ist damit technisch nicht auslieferbar, ohne öffentlich zu werden.
- **Zwei unabhängige reproduzierbare Builds als Release-Gate**; Divergenz blockiert das Release.
- **Kein stiller Auto-Update.** Updates werden angezeigt und lokal gegen Log und Schwellwert-Signatur geprüft.
- `cargo-vet` / `cargo-crev`, gepinnte und hash-verifizierte Dependencies, minimale Dependency-Fläche, Vendoring.
- Verteilung über F-Droid und direkte signierte Binaries, nicht nur über App-Stores.

## 2.12 Plattformen

| Plattform | Status |
|---|---|
| **Android** | Voll. Foreground-Service ermöglicht dauerhafte Erreichbarkeit und Mesh. |
| **Windows / Linux** | Voll. Dauerbetrieb im Tray; deckt als Zweitgerät den Tag ab. |
| **iOS** | **Eingeschränkt.** Kein persistenter Hintergrundprozess, kein Onion-Service im Hintergrund. Nachrichten werden beim Öffnen der App und in den unregelmäßigen Background-Refresh-Fenstern geholt; der PC im selben Kompartiment empfängt und synchronisiert später nach. **Keine Instant-Benachrichtigungen** — Push ginge nur über APNs und damit über einen Server (§6). |

---

# 3. Architektur

```
┌───────────────────────────────────────────────────────────┐
│  UI (Flutter · Android/Windows/Linux voll, iOS reduziert)  │
│  Kompartiment-Führung · Assurance-Anzeige · ehrl. Status   │
└───────────────┬───────────────────────────────────────────┘
                │ flutter_rust_bridge (FFI)
┌───────────────▼───────────────────────────────────────────┐
│  Rust Core                                                 │
│  identity    Ed25519 = Onion-v3 · Entropie-Gate            │
│  compartments Onion-Kompartimente · Per-Kontakt-Client-Auth│
│               · granulare Revocation                       │
│  contacts    Invitation-only · Verifikation über gem.      │
│              Geheimnis · Assurance-Level                   │
│  crypto      PQXDH · Double Ratchet · MLS · deniable MACs  │
│  delivery    persistente Sendequeue · Multi-Device-Routing │
│              · Sync-Fenster · E2E-ACK                      │
│  sync        P2P-Verlaufs-Sync zwischen eigenen Geräten    │
│  groups      MLS + Peer-Sequencer · Transcript-Gossip      │
│              · Pairwise-Fanout                             │
│  privacy     Padding · Alltags-Shaping · Identifier-Isolat.│
│  transport   ├ Tor (Onion + Client-Auth, Snowflake/meek,   │
│  (Trait)     │   Vanguards) — Arti-Ziel, C-tor sandboxed   │
│              └ BLE / Wi-Fi Direct / mDNS (Mesh, PSI-Beacons)│
│  storage     SQLCipher · DEK im Keystore · Crypto-Erase    │
└────────────────────────────────────────────────────────────┘

Externe Komponenten: keine.
Einzige Fremdinfrastruktur: das öffentliche Tor-Netz (Freiwilligennetz,
sieht keine Inhalte, keine Betreiber-Backend-Rolle).
```

**Warum Rust-Core:** eine einzige auditierbare Codebasis für alles Sicherheitskritische, Memory Safety, native Bindings für Tor/Arti, Krypto und SQLCipher.
**Warum Flutter-UI:** eine UI-Codebasis für alle Plattformen bei akzeptabler Nativität.

---

# 4. Designkonzept

## 4.1 Prinzipien

1. **Sicherheit ohne Reibung** — Verschlüsselung ist selbstverständlich, nicht erklärungsbedürftig.
2. **Ehrlichkeit im Status** — die App behauptet nie, etwas sei zugestellt, wenn es das nicht ist. Wartezustände werden benannt.
3. **Assurance sichtbar** — 🟢 verifiziert / 🔵 bestätigt / ⚪ niedrig, mit Ein-Klick-Weg zur Verbesserung.
4. **Kompartimente verständlich führen** — die Trennung nach Kontext ist die zentrale Sicherheitsentscheidung des Nutzers und braucht klare, nicht-technische Sprache.
5. **Ruhiges, reduziertes Interface** — vertraute Messenger-Konventionen, keine Lernkurve.
6. **Keine Sicherheits-Regler** — bewusst nichts zu konfigurieren, was das Netzverhalten ändert (§2.9).

## 4.2 Zentrale Flows

**Onboarding (< 60 s):** Identität wird lokal erzeugt → Kompartiment-Grundeinrichtung → App-Passcode/Biometrie → fertig. Keine Nummer, keine Mail, kein Konto.

**Kontakt hinzufügen:** QR-Scan (bevorzugt) · NFC · Invitation-Link mit anschließender Verifikation über gemeinsames Geheimnis.

**Kontakt entfernen/revozieren:** Ein Schritt entzieht Client-Auth-Credential, Mesh-Sichtbarkeit und Zustellberechtigung gleichzeitig.

**Chat:** Textnachrichten, Anhänge, Sprachnachrichten, Zitieren, Reaktionen; selbstlöschende Nachrichten aktiv per Default mit sichtbarem Timer.

**Sicherheitsübersicht:** Fingerprints, verlinkte Geräte, Kompartimente, Revocations, aktiver Transportweg.

## 4.3 Visuelle Identität

Metapher „Tresor": solide, präzise, ruhig. Tiefes Anthrazit mit einem Akzentton für „gesichert verbunden". Inter für UI, Monospace für Fingerprints. Dark-First, Light gleichwertig, WCAG AA. Adaptive Layouts: Single-Pane mobil, Master-Detail auf Desktop.

---

# 5. Entwicklungsplan

| Phase | Inhalt | Dauer |
|---|---|---|
| **0 — Fundament** | Threat Model & Krypto-Whitepaper · Spikes (Tor-Client-Auth, Arti-Reifegrad, flutter_rust_bridge, SQLCipher) · CI mit reproduzierbaren Builds, Binary-Transparency-Log, Schwellwert-Signatur · Design System | M1–M2 |
| **1 — Kern-MVP** | Identität & Kompartimente · Invitation + QR-Verifikation · PQXDH + Double Ratchet · Tor-Transport mit Client-Auth · SQLCipher · 1:1-Textchat, beide online · Android + Desktop | M3–M6 |
| **2 — Zustellbarkeit** | Persistente Sendequeue · **Multi-Device-Sync (vorgezogen, tragend für Zustellung)** · Sync-Fenster · E2E-ACK · Anhänge & Sprachnachrichten · Foreground-Service / Tray | M7–M10 |
| **3 — Anti-SIGINT-Härtung** | Snowflake/meek als Default · Vanguards · Traffic-Shaping · Bootstrap-Entschärfung · Identifier-Isolation · Remote-Verifikation über gemeinsames Geheimnis | M11–M13 |
| **4 — Gruppen & Mesh** | MLS + Peer-Sequencer + Transcript-Gossip · Pairwise-Modus · BLE/Wi-Fi-Direct mit PSI-Beacons · epidemisches Routing | M14–M17 |
| **5 — Audit & Release** | Externes Security-Audit + Fixes · Performance/Akku · iOS-Client (reduziert) · Lokalisierung, Accessibility · F-Droid + signierte Binaries · **1.0** | M18–M20 |

**Team:** 2× Rust/Krypto, 1× Netzwerk/Tor, 2× Flutter, 1× Design, 1× externer Security-Reviewer, 1× PM/QA.

**Größte Risiken:**

| Risiko | Maßnahme |
|---|---|
| Arti-Onion-Client-Auth nicht rechtzeitig produktionsreif | C-tor sandboxed als Interim, Migrationspfad offen halten; früher Spike in Phase 0 |
| Akkuverbrauch durch Dauererreichbarkeit + Tor | Frühe Messung, Shaping-Budget, Doze-Optimierung |
| Kleines Anonymitätsset bei Launch | Uniformität (§2.9), Mitschwimmen im Fremdtraffic, Wachstum als Sicherheitsziel priorisieren |
| Kompartiment-Konzept überfordert Nutzer | Frühe Usability-Tests; sinnvolle Voreinstellung statt Zwang zur Konfiguration |

---

# 6. Offener Punkt: iOS-Benachrichtigungen

Der Lösungsraum ist eng, weil APNs prinzipbedingt ein Server ist. Kandidaten in absteigender Attraktivität:

1. **Lokales Wecken über den eigenen PC**, wenn beide Geräte im selben Netz sind — kein Fremdserver, aber nur zu Hause bzw. im Büro wirksam.
2. **Background-App-Refresh + PC-Sync** — verzögert und unregelmäßig, vollständig serverlos, sofort umsetzbar. **Aktueller Stand.**
3. **Opt-in Blind-Push mit ephemeren, rotierenden Tokens** — der einzige Weg zu Instant-Push. Verlässt die Serverlosigkeit und müsste als klar deklarierte Ausnahme gebaut werden, die das Netzverhalten der Nicht-Nutzer nicht verändert.

Empfehlung: Android/Desktop-first, iOS mit Option 1+2 starten, Option 3 nur nach bewusster Grundsatzentscheidung.

---

# 7. Konsolidiertes Backlog

Priorisierung: **P0** MVP-kritisch · **P1** Release 1.0 · **P2** danach.

### E1 — Identität & Kompartimente
| ID | Story | Prio |
|---|---|---|
| ID-1 | Lokale Identitätserzeugung, Ed25519 = Onion-v3-Adresse | P0 |
| ID-2 | Entropie-Gate vor Schlüsselerzeugung | P0 |
| ID-3 | Onion-Kompartimente mit Per-Kontakt-Client-Auth | P0 |
| ID-4 | Granulare Ein-Schritt-Revocation (Onion + Mesh + Zustellung) | P1 |
| ID-5 | Kontextbasierte Kompartiment-Führung im UX | P1 |
| ID-6 | Quer-signierte freiwillige Schlüsselrotation | P2 |

### E2 — Kontaktaufbau & Vertrauen
| ID | Story | Prio |
|---|---|---|
| CT-1 | Invitation-only Kontaktaufbau (QR / NFC / Link), einmalig & replay-fest | P0 |
| CT-2 | Verifikation über gemeinsames Geheimnis (stimmklonungsfest) | P1 |
| CT-3 | Assurance-Level sichtbar (🟢/🔵/⚪) inkl. Verbesserungsweg | P0 |
| CT-4 | Kontakte blockieren | P1 |

### E3 — Kryptografie
| ID | Story | Prio |
|---|---|---|
| CR-1 | PQXDH-Schlüsselaustausch (X25519 + ML-KEM) | P0 |
| CR-2 | Double Ratchet für alle 1:1-Nachrichten | P0 |
| CR-3 | Verschlüsselte Anhänge (XChaCha20-Poly1305) | P0 |
| CR-4 | Abstreitbare Authentisierung | P2 |

### E4 — Transport & Anti-SIGINT
| ID | Story | Prio |
|---|---|---|
| TR-1 | Tor-Onion-Transport mit Pflicht-Client-Auth | P0 |
| TR-2 | Snowflake/meek als Standardtransport | P1 |
| TR-3 | Vanguards-lite + Standard-Guard-Policy | P1 |
| TR-4 | Traffic-Shaping auf Alltagsprofil, session-gebunden | P1 |
| TR-5 | Einheitliches, nicht konfigurierbares Netzverhalten | P0 |
| TR-6 | Entschärfter Erst-Bootstrap (gestreut, Out-of-band-Bridges) | P1 |
| TR-7 | Cross-Transport-Identifier-Isolation | P1 |
| TR-8 | C-tor in Prozessisolation + seccomp; Arti-Migration | P1 |

### E5 — Zustellung
| ID | Story | Prio |
|---|---|---|
| DL-1 | Persistente Ausgangswarteschlange mit Auto-Retry | P0 |
| DL-2 | Multi-Device-Zustellung an das erreichbare Gerät | P0 |
| DL-3 | P2P-Verlaufs-Sync zwischen eigenen Geräten | P0 |
| DL-4 | Ausgehandelte Sync-Fenster aus dem Kontaktgeheimnis | P1 |
| DL-5 | E2E-ACK; ehrlicher Status „wartet auf Erreichbarkeit" | P0 |
| DL-6 | Dauererreichbarkeit: Android Foreground-Service, Desktop-Tray | P0 |
| DL-7 | Randomisierte Descriptor-Publikationsfenster | P1 |

### E6 — Messaging
| ID | Story | Prio |
|---|---|---|
| MS-1 | 1:1-Textchat, Zitieren, Löschen, Reaktionen | P0 |
| MS-2 | Bilder, Dateien, Sprachnachrichten | P1 |
| MS-3 | Selbstlöschende Nachrichten als Default | P1 |
| MS-4 | Gruppen: MLS + Peer-Sequencer + Transcript-Gossip | P1 |
| MS-5 | Pairwise-Fanout-Modus für Hochrisiko-Kleingruppen | P2 |
| MS-6 | E2E-Sprach-/Videoanrufe über Tor | P2 |

### E7 — Mesh
| ID | Story | Prio |
|---|---|---|
| ME-1 | BLE / Wi-Fi Direct / mDNS Transport | P1 |
| ME-2 | PSI-Beacons mit Challenge-Response-Frische | P1 |
| ME-3 | Rotierende Identifier auf allen Ebenen | P1 |
| ME-4 | Capability-gated epidemisches Routing mit TTL/Hop/Budget | P1 |
| ME-5 | Beacon-Rate-Limits, konstanter Prüfaufwand | P1 |
| ME-6 | Mesh-Sichtbarkeit pro Kontakt schaltbar | P1 |

### E8 — Lokale Sicherheit
| ID | Story | Prio |
|---|---|---|
| SE-1 | SQLCipher-Datenbank, DEK im Plattform-Keystore | P0 |
| SE-2 | App-Passcode / Biometrie mit Auto-Lock | P0 |
| SE-3 | Plattform-Auto-Backup deaktiviert, keine Klartext-Notifications | P0 |
| SE-4 | Crypto-Erase-Wipe | P1 |
| SE-5 | Lokale Gerätemigration per QR | P1 |
| SE-6 | Duress-PIN / Decoy / Hidden Volume | P2 |

### E9 — Lieferkette & Vertrauen
| ID | Story | Prio |
|---|---|---|
| SC-1 | m-of-n-Schwellwert-Signatur über mehrere Jurisdiktionen | P0 |
| SC-2 | Erzwungene Binary Transparency im Client | P0 |
| SC-3 | Zwei unabhängige reproduzierbare Builds als Release-Gate | P1 |
| SC-4 | Kein stiller Auto-Update | P1 |
| SC-5 | cargo-vet/-crev, gepinnte Dependencies | P0 |
| SC-6 | Öffentliches Threat Model & Krypto-Whitepaper | P0 |
| SC-7 | Externes Security-Audit vor 1.0 | P1 |
| SC-8 | F-Droid + signierte Direkt-Binaries | P1 |
| SC-9 | Bug-Bounty | P2 |

### E10 — Plattform & Qualität
| ID | Story | Prio |
|---|---|---|
| PL-1 | Android + Windows + Linux aus einer Codebasis | P0 |
| PL-2 | iOS-Client mit dokumentierten Einschränkungen | P1 |
| PL-3 | Lokalisierung (DE/EN), Accessibility WCAG AA | P1 |
| PL-4 | Akku-/Performance-Optimierung unter Dauer-Tor | P1 |

---

# 8. Restrisiken (abschließend, ehrlich)

Nach sieben Iterationen sind keine Protokollschwächen mehr offen. Was bleibt, ist prinzipiell hart:

1. **Anonymitätsset / Nutzerzahl** — nicht technisch lösbar. Gemindert durch Uniformität und Mitschwimmen im Fremdtraffic. **Die wichtigste offene Größe.**
2. **Menschliche Faktoren** — übersprungene Verifikation, ein Kontakt, der zum Informanten wird. Begrenzt durch Assurance-Anzeige, selbstlöschende Nachrichten, Kompartimentierung und sofortige Revocation; nicht eliminierbar.
3. **Globale Langzeitbeobachtung** — auf Stand der Technik gemindert; ein theoretisches Restrisiko, das für jedes existierende System weltweit gilt.
4. **Verfügbarkeit unter Totalzensur** — Pluggable Transports und Mesh mildern, garantieren nichts.
5. **iOS-Zustellqualität** — Plattformzwang, siehe §6.

Außerhalb des Scopes und in Nutzerverantwortung: Geräteverlust und -beschlagnahme, Tastatur-/IME-Leaks, Endpoint-Kompromittierung.

**Leitsatz:** Lieber ehrlich benannte Restrisiken als ein falsches Absolutversprechen.

---

# Anhang A — Verworfene Ansätze

Damit sie nicht versehentlich zurückkehren:

| Verworfen | Grund |
|---|---|
| **Usernamen / globales Verzeichnis** | Sybil-/Eclipse-Angriffe ermöglichen MITM bei der Namensauflösung; kein serverfreies Register ist dagegen robust |
| **Kademlia-DHT für Discovery oder Mailboxen** | Sybil/Eclipse; Timing-Korrelation zwischen Ablage und Abruf rekonstruiert den Kommunikationsgraphen; DoS-anfällig |
| **Transparency-Log für Usernamen** | Erfordert Log-Betreiber → verletzt Serverlosigkeit |
| **Untrusted Queue-Relays (SimpleX-Modell)** | Sind Server → verletzt Prio 2 |
| **Persönliche Mailbox auf Zusatzgerät** | 24/7-Onion-Traffic an Residentialleitung verrät den Haushalt; Ortsbindung der Pseudonym-Identität; zusätzliche Angriffsfläche |
| **Zustellung über gemeinsame Kontakte** | Der Träger lernt, dass zwischen zwei Parteien Verkehr existiert → Kontaktgraph-Leak |
| **Per-Kontakt-Onion-Services** | Descriptor-Volumen verrät Kontaktanzahl und ermöglicht Re-Linking; nicht skalierbar auf Mobilgeräten |
| **Constant-Rate-Mix („Maximum Security"-Modus)** | Perfekt gleichmäßiger 24/7-Verkehr ist selbst ein Fingerprint und partitioniert die Nutzerbasis |
| **I2P als wählbare Alternative** | Jede wählbare Transportvariante partitioniert das Anonymitätsset; Transport-Trait bleibt für eine spätere geschlossene Migration erhalten |
| **Direkter P2P-Modus ohne Tor** | Legt IP-Adressen offen → verletzt Prio 1 |
| **Blind-Push-Relay für iOS (als Default)** | Ist ein Server; nur als bewusst deklarierte Opt-in-Ausnahme denkbar (§6) |
| **SAS-Sprachvergleich als hinreichende Verifikation** | Echtzeit-Stimmklonung macht ihn gegen staatliche MITM unzuverlässig |
