# Spike S1 — Tor-Stack: Arti vs. C-tor

**Spec:** `spec/phase0-spikeplan.md` §2 (S1), §4 (GATE-1), §6 (R-1)
**Gemessener Stand:** arti 0.44.0 (crates.io), Abruf 2026-07-25
**Umgebung:** Windows 11, x86_64-pc-windows-msvc, rustc 1.97.1 (8bab26f4f)
**Timebox:** abgebrochen, sobald weitere Arbeit die GATE-1-Entscheidung nicht
mehr verbessert hat. Was offen blieb, steht in §4 und §5.

Zitat der Spec-Frage (§2, S1):
> „Unterstützt Arti Onion-Services **mit v3 Client Authorization**
> produktionsreif? Falls nein, ist C-tor sandboxed über 4 Plattformen
> einbettbar?"

Zitat der Erfolgskriterien (§2, S1):
> - Client-Auth funktional auf **allen** Zielplattformen
> - Onion-Aufbau < 20 s (p50), < 60 s (p95)
> - Nicht-autorisierter Descriptor-Abruf schlägt in 100 % der Versuche fehl

---

## 1. Messergebnisse gegen jedes Erfolgskriterium

### K1 — Client-Auth funktional auf allen Zielplattformen

Zielplattformen laut ADR-12 (`spec/engineering-setup.md` §1): Android, Windows,
Linux; iOS reduziert.

| Plattform | Ergebnis | wie gemessen |
|---|---|---|
| Windows x86_64 | **teilweise: kompiliert + läuft, Netzpfad nicht abschließbar** | `cargo build --release` von `spikes/S1/arti-probe` erfolgreich; Binary gestartet, Bootstrap blieb hängen (siehe K2) |
| Android aarch64 | **nicht messbar** | `cargo check --target aarch64-linux-android` bricht in `cc-rs` ab: kein Android-NDK vorhanden. Protokoll: `ergebnisse/T-plattformen.txt` |
| Linux x86_64 | **nicht gemessen** | kein Linux-Host und kein Container in dieser Umgebung |
| iOS | **nicht gemessen** | kein macOS-Host |

Ergebnis K1: **1 von 3 Zielplattformen angefasst, 0 von 3 vollständig
nachgewiesen.** Kriterium ist damit **nicht erfüllt** — nicht weil Arti
scheitert, sondern weil die Messung hier nicht durchführbar ist.

Messbare Teilaussagen zur Portierbarkeit (aus `ergebnisse/T-plattformen.txt`):

| Größe | Wert |
|---|---|
| Crates im Abhängigkeitsgraph (`cargo tree \| sort -u`) | 414 |
| C-basierte `-sys`-Crates im Graph | 3 (`libsqlite3-sys`, `liblzma-sys`, `zstd-sys`) |
| davon abwählbar | 2 (über Feature `compression`) |
| nicht abwählbar | `libsqlite3-sys` (rusqlite ist in `tor-dirmgr-0.44.0/Cargo.toml` Zeile 91 nicht optional) |
| Binärgröße Release (Windows, mit Debug-Info) | 15.386.112 Bytes |
| `cargo check` des vollen arti-Graphen (kalt, Windows) | 68 s |
| Rebuild `arti-probe` nach Feature-Wechsel | 87 s / 93 s |

Konsequenz: Der Satz „Zielarchitektur **Arti** (Rust, memory-safe)"
(`spec/gesamtkonzept.md` §2.5) gilt für den Tor-Protokollkern, **nicht** für den
gesamten mitgelieferten Graphen: SQLite (C) ist über `tor-dirmgr` verpflichtend.

### K2 — Onion-Aufbau < 20 s (p50), < 60 s (p95)

**Nicht messbar in dieser Umgebung.** Kein einziger Zeitwert wird berichtet.

Was tatsächlich gemessen wurde (`ergebnisse/T-netcheck.txt`,
`ergebnisse/T-arti-bootstrap-versuch.txt`):

| Schritt | Ergebnis |
|---|---|
| TCP zu Tor-Directory-Authorities | 6 von 8 erreichbar (19–181 ms) |
| TCP zu Tor-Fallback-Directories (Liste aus `tor-dircommon-0.44.0/data/fallback_dirs.rs`) | 11 von 12 erreichbar (12–130 ms) |
| Arti-Link-Handshake zu 3 Relays | 3 von 3 erfolgreich (`Completed handshake with peer`, 0,5–1,1 s nach Start) |
| Einhop-Circuits zu diesen Relays | aufgebaut |
| Konsens-Download | **kein Byte**; `cache/dir_blobs` blieb leer |
| Verlauf | nach 60 s je Circuit `DESTROY … Circuit expired for being too dirty or old`; danach über 8 min kein Fortschritt und keine Warnung |
| Gesamtlaufzeit ohne Bootstrap-Abschluss | 1. Lauf > 15 min, 2. Lauf > 8 min |

Da der Bootstrap nie abschließt, wurden **M2 (Zeit bis Onion-Service
`Running`)** und **M3 (Verbindungszeiten p50/p95)** nie erreicht. Es gibt dazu
**keine Zahlen**, und es werden hier auch keine geschätzt.

Anmerkung zur Spec: „Onion-Aufbau" ist in §2 nicht eindeutig — es kann die Zeit
bis zur Erreichbarkeit des eigenen Dienstes oder die Verbindungszeit eines
Clients meinen. Das Messprogramm `arti-probe` erhebt beides getrennt (M2 und
M3); die Spec sollte das vor der Wiederholungsmessung präzisieren.

### K3 — Nicht-autorisierter Descriptor-Abruf schlägt in 100 % der Versuche fehl

**Gemessen, auf der kryptografischen Schicht, offline.**
Programm: `spikes/S1/desc-auth`, Rohdaten: `ergebnisse/T-desc-auth.txt`.
Es baut mit `tor-netdoc 0.44.0` (`HsDescBuilder`, derselbe Pfad, den
`tor-hsservice/src/publish/descriptor.rs` beim Publizieren nutzt) einen
v3-Descriptor mit Restricted Discovery und versucht ihn zu entschlüsseln.

| Test | Versuche | erfolgreich | abgewiesen | Ergebnis |
|---|---|---|---|---|
| T2 autorisierte Clients | 8 | 8 | 0 | PASS |
| T3 nicht-autorisierte Clients (frischer Schlüssel je Versuch) | 500 | 0 | 500 | PASS — Abweisungsquote 100,0000 % |
| T4 Abruf ganz ohne Schlüssel (HSDir/Enumerator) | 500 | 0 | 500 | PASS |
| T5 Kontrolle: Descriptor **ohne** Client-Auth, Abruf ohne Schlüssel | 1 | 1 | 0 | PASS (belegt, dass T3/T4 nicht am Testaufbau scheitern) |

**K3 ist erfüllt: 1000 von 1000 unberechtigten Abrufen scheitern (100 %).**
Einschränkung: gemessen wurde die Descriptor-Kryptografie, nicht der Abruf über
einen echten HSDir. Der in der Spec genannte „eigene HSDir-Beobachter"
(Methodenschritt 3) wurde **nicht** gebaut.

Zusatzmessungen aus demselben Lauf, relevant für das Threat Model:

| Größe | Wert | Bedeutung |
|---|---|---|
| Descriptor mit Client-Auth (8 Clients, 3 Intro-Points) | 14.427 Bytes | — |
| Descriptor **ohne** Client-Auth, sonst identisch | 14.427 Bytes | gleiche Länge |
| Für den HSDir sichtbare Schlüsselwörter, mit vs. ohne Client-Auth | identisch (`hs-descriptor`, `descriptor-lifetime`, `descriptor-signing-key-cert`, `revision-counter`, `superencrypted`, `signature`) | ein HSDir kann am Descriptor **nicht** erkennen, ob Client-Auth aktiv ist |
| Descriptor-Größe bei 1 / 5 / 10 / 20 / 50 / 60 / 70 / 80 Clients | jeweils 14.427 Bytes | Kontaktanzahl ist bis 80 **nicht** aus der Größe ableitbar |
| bei 100 / 160 / 200 Clients | 28.292 Bytes | |
| bei 300 / 350 Clients | 42.157 Bytes | |
| bei 400 / 500 Clients | 56.027 Bytes | über der 50-kB-Grenze (`HSV3MaxDescriptorSize`) |
| größte getestete Clientzahl unter 50 kB (bei 3 Intro-Points) | 350 | Bibliotheks-Empfehlung `MAX_RESTRICTED_DISCOVERY_CLIENTS` = 160 |

Das stützt zwei Zeilen aus `spec/threat-model.md` §4/A3 messtechnisch:
„HSDir-Enumeration" (○) und „Rückschluss auf Kontaktanzahl aus
Descriptor-Volumen" (○) — letzteres gilt gemessen bis 80 Kontakte je
Kompartiment, bei den in `spec/gesamtkonzept.md` §2.2 genannten 2–5
Kompartimenten reichlich.

### K-Zusatz — Reifegrad der API (kein Spec-Kriterium, aber GATE-1-relevant)

Gemessen per Compilerlauf, reproduzierbar mit
`bash spikes/S1/pruefe-api-oberflaeche.sh`, Rohdaten
`ergebnisse/T-api-oberflaeche.txt`.

| Frage | Messung | Ergebnis |
|---|---|---|
| Ist Restricted Discovery service-seitig ohne `experimental-api` nutzbar? | `cargo check` von `api-nonexp` | **ja**, übersetzt |
| Ist die Client-seitige Schlüsselverwaltung ohne `experimental-api` nutzbar? | `cargo check --features client-key-api` | **nein**: `error[E0599]: no method named 'generate_service_discovery_key' found for reference '&TorClient<R>'` |
| Ist das Feature `restricted-discovery` als experimentell markiert? | `cargo info tor-hsservice` | nein — `restricted-discovery = []`, enthalten in `full`, **nicht** in `experimental` |
| Ist `launch_onion_service` experimentell? | Quelltext | nein (`arti-client-0.44.0/src/client.rs:1917`) |
| Ist `launch_onion_service_with_hsid` experimentell? | Quelltext | **ja** (`client.rs:1996`) — relevant, weil Vault die Onion-Adresse aus der eigenen Ed25519-Identität ableitet (`spec/gesamtkonzept.md` §2.1) |

Belegstellen im Quelltext, die gegen „produktionsreif" sprechen:

1. `arti-client-0.44.0/src/client.rs:388`
   ```
   // TODO: decide whether this should use get_or_generate before making it
   // non-experimental
   ```
   → die client-seitige Schlüssel-API hat noch eine offene Designfrage.

2. `tor-hsservice-0.44.0/src/config/restricted_discovery.rs:242`
   ```
   // TODO: this is a footgun. We might want to rethink this before we make
   // the restricted-discovery feature non-experimental:
   ```
   → die Autoren behandeln das Feature im Code weiterhin als noch nicht
   nicht-experimentell, obwohl das Cargo-Manifest es nicht so kennzeichnet.

3. `tor-hsservice-0.44.0/src/config/restricted_discovery.rs:50–62`
   ```
   //! Removing a previously authorized client from `static_keys` or `key_dirs`
   //! does **not** guarantee its access will be revoked.
   //! ...
   //! **Restricted discovery mode is a DoS resistance mechanism,
   //! _not_ a substitute for conventional access control.**
   ```
   → **direkter Konflikt mit dem Vault-Design.** `spec/gesamtkonzept.md` §2.2
   nutzt Client-Auth als Zugangskontrolle *und* als Revocation-Mechanismus
   („granulare Revocation"), `spec/threat-model.md` §4/A4 stuft „Ein-Schritt-
   Revocation" als ○ ein, und S3 fordert Wirksamkeit < 5 min. Arti rotiert bei
   Änderung der Clientliste **keine** Intro-Points; ein entzogener Kontakt kann
   die ihm bekannten Intro-Points weiter nutzen. Vault muss die Rotation selbst
   erzwingen. Das ist eine Anforderung an die eigene Implementierung, kein
   Arti-Defekt — aber sie steht heute in keiner Spec.

4. Widerspruch in der Dokumentation derselben Datei:
   Modul-Doku Zeile 27–34 „is automatically reloaded if `watch_configuration`
   is `true`" vs. Struct-Doku Zeile 180–185 „will *not* be monitored for
   updates". Der Code (`publish/reactor.rs:1210` und `:1241`) aktualisiert
   die autorisierten Clients tatsächlich in beiden Pfaden. Die Doku ist
   veraltet, nicht der Code — festgestellt durch Lesen von
   `reactor.rs:1203–1269`.

5. **Defekt für Vault gemessen** (`ergebnisse/T-desc-auth.txt`, T8):
   Restricted Discovery aktiv mit **0** autorisierten Clients erzeugt einen
   internen Fehler (`Bug/BadApiUsage`,
   `tor-netdoc-0.44.0/src/doc/hsdesc/build/middle.rs:59`;
   in `tor-hsservice-0.44.0/src/publish/descriptor.rs:94` ebenfalls
   `internal!(...)`), obwohl die API-Doku `Some(&[])` ausdrücklich als
   zulässigen Fall beschreibt. Vault erreicht diesen Zustand, sobald der letzte
   Kontakt eines Kompartiments revoziert wird.

Objektive Reifeindikatoren (`grep -rn TODO`, arti 0.44.0):
`tor-hsservice` 150, `tor-hsclient` 54, `arti-client` 51, `tor-keymgr` 43.
Diese Zahlen sind ein Indikator, kein Urteil.

---

## 2. Empfehlung

**Ergebnis: bestanden mit Auflagen — Fallback-Kaskade nicht ausgelöst.**

Begründung entlang der Kriterien:

- K3 (das sicherheitstragende Kriterium, `spec/threat-model.md` A3) ist mit
  1000/1000 erfüllt. Die Client-Auth-Kryptografie von Arti ist wirksam.
- K1 und K2 sind **nicht gemessen** — aus Umgebungsgründen, nicht wegen eines
  Befunds gegen Arti. Es liegt kein Beleg vor, dass Arti sie verfehlt.
- Der Abbruchgrund aus §4 („Scheitert S1 vollständig — kein Client-Auth auf
  keiner Plattform") liegt **nicht** vor.
- Der Fallback „C-tor sandboxed" wurde **nicht** geprüft (§4). Er bleibt als
  Option offen; es gibt keinen Anlass, ihn jetzt zu ziehen.
- Ein Start ohne Client-Auth wird nicht empfohlen und ist laut §2 kein
  zulässiger Fallback.

**Auflagen, ohne die GATE-1 nicht geschlossen werden darf:**

- A1: K1 und K2 auf Android, Linux und Windows nachmessen (siehe §5). Vor
  diesem Nachweis darf GATE-1 nur als *vorläufig* akzeptiert gelten.
- A2: Die client-seitige Schlüsselverwaltung liegt hinter `experimental-api`
  (kein Semver-Schutz). Vault muss diese Abhängigkeit entweder kapseln
  (eigenes Adapter-Modul mit Vertragstests) oder die Schlüssel selbst im
  Arti-Keystore ablegen. Zu entscheiden vor Phase 1.
- A3: Revocation darf sich **nicht** allein auf das Entfernen aus der
  Clientliste stützen. Intro-Point-Rotation muss aktiv erzwungen werden
  (Eingabe für S3 und `spec/protokoll-spec.md`).
- A4: Der Leerfall „Kompartiment ohne autorisierte Kontakte" muss in Vault
  abgefangen werden, bevor er Arti erreicht.
- A5: Obergrenze Kontakte je Kompartiment festlegen. Gemessen: bis 80 Kontakte
  ist die Descriptor-Größe konstant (kein Volumen-Leak), 350 passen technisch
  unter 50 kB, Arti empfiehlt 160. Vorschlag: hartes Limit 80 je Kompartiment,
  weil dort zusätzlich das Metadaten-Argument aus §2.2 greift.

---

## 3. Was nachweislich funktioniert vs. was nur kompiliert

**Nachweislich (mit Messwerten):**
- Bau eines v3-Descriptors mit Restricted Discovery über `tor-netdoc 0.44.0`
- Entschlüsselung durch autorisierte Clients (8/8)
- Abweisung nicht autorisierter Clients und schlüsselloser Abrufe (1000/1000)
- Ununterscheidbarkeit des Descriptors mit/ohne Client-Auth für den HSDir
- Verfügbarkeit bzw. Nichtverfügbarkeit der API-Oberfläche ohne
  `experimental-api` (per Compiler belegt)
- TCP-Erreichbarkeit des Tor-Netzes, Link-Handshake und Circuit-Aufbau

**Kompiliert und startet, aber nicht durchgemessen:**
- `spikes/S1/arti-probe` (Onion-Service mit `static_keys`, autorisierter und
  nicht autorisierter Client, Zeitmessung). Läuft bis zum Bootstrap und bleibt
  dort hängen.

**Gar nicht angefasst:**
- C-tor als Subprozess mit seccomp-Sandbox (Methodenschritt 4)
- eigener HSDir-Beobachter (Methodenschritt 3)
- Speicherverbrauch (Methodenschritt 5)

---

## 4. Was nicht geprüft werden konnte — und warum

| # | Nicht geprüft | Grund | Was nötig wäre |
|---|---|---|---|
| 1 | Onion-Aufbauzeiten (K2) | Arti-Bootstrap schließt hier nicht ab: TCP/TLS/Circuits ok, Konsens-Download liefert nichts (`ergebnisse/T-arti-bootstrap-versuch.txt`) | Ein Host mit ungefiltertem Tor-Zugang. Danach `spikes/S1/arti-probe/target/release/bootstrap-timing 12 240` |
| 2 | Client-Auth auf Android | kein Android-NDK, kein Gerät; `cargo check --target aarch64-linux-android` bricht in `cc-rs` ab | NDK r26+, `cargo-ndk`, ein Testgerät; danach derselbe Probe-Lauf |
| 3 | Client-Auth auf Linux | kein Linux-Host/Container in dieser Umgebung | Linux-x86_64-Host oder Container |
| 4 | iOS | kein macOS-Host | macOS + iOS-Gerät; laut ADR-12 ohnehin reduziert |
| 5 | C-tor sandboxed (Fallbackzweig, Methodenschritt 4) | kein `tor`-Binary vorhanden; seccomp existiert auf Windows nicht | Linux-Host mit `tor`, `seccomp`-Profil; Android-seitig Prüfung, ob C-tors Sandbox unter Android-SELinux greift |
| 6 | Eigener HSDir-Beobachter (Methodenschritt 3) | erfordert Betrieb eines Relays im HSDir-Ring bzw. ein privates Tor-Testnetz | `chutney`-Testnetz oder Relay mit HSDir-Flag |
| 7 | Speicherverbrauch (Methodenschritt 5) | ohne laufenden Onion-Service nicht sinnvoll messbar | zusammen mit #1 |
| 8 | Verhalten bei Revocation über die Zeit | ist Gegenstand von S3, nicht von S1 | S3 |
| 9 | Snowflake/meek als Standard-Transport (`spec/gesamtkonzept.md` §2.5) | nicht Teil der S1-Methode; Feature `pt-client` wurde nicht aktiviert | eigener Spike oder Erweiterung von S1 |

---

## 5. Was der Mensch braucht, um die offenen Punkte zu schließen

1. **Ein Linux-Host mit echtem Tor-Zugang** (kein gefiltertes Egress).
   Darauf: `cargo run --release --bin bootstrap-timing -- 20 240`.
   Liefert M1 (Bootstrap), M2 (Zeit bis `Running`) und M3 (p50/p95) sowie den
   Ende-zu-Ende-Nachweis, dass ein nicht autorisierter Client scheitert.
   Erst dann sind K1 (Linux) und K2 entschieden.
2. **Android-Toolchain** (NDK r26+, `cargo-ndk`) und ein Mittelklasse-Gerät.
   Damit `cargo ndk -t arm64-v8a check` und anschließend derselbe Messlauf auf
   dem Gerät. Wichtig: Feature `rustls` statt `native-tls` (in dieser Umgebung
   gemessen: `native-tls` verlangt cross-kompiliertes OpenSSL) und ein
   `CryptoProvider` muss explizit installiert werden — bei `rustls` ohne
   eindeutige Provider-Wahl paniert der Prozess beim Start
   (`rustls-0.23.42/src/crypto/mod.rs:249`, hier reproduziert).
3. **Entscheidung zu Auflage A2** (Umgang mit `experimental-api`): entweder
   Kapselung akzeptieren oder Schlüssel selbst in den Arti-Keystore schreiben.
4. **Ergänzung der Spec** um die Intro-Point-Rotation bei Revocation (A3) und
   um eine eindeutige Definition von „Onion-Aufbau" in §2.
5. **Kontaktobergrenze je Kompartiment** festlegen (A5).

---

## 6. Verzeichnis der Artefakte

| Pfad | Inhalt |
|---|---|
| `spikes/S1/desc-auth/` | Offline-Nachweis K3 (Descriptor-Client-Auth), lauffähig ohne Netz |
| `spikes/S1/api-nonexp/` | Compiler-Nachweis der API-Oberfläche ohne `experimental-api` |
| `spikes/S1/arti-probe/` | Ende-zu-Ende-Messprogramm gegen das echte Tor-Netz (M1–M4) |
| `spikes/S1/netcheck/` | Erreichbarkeitsprüfung des Tor-Netzes |
| `spikes/S1/pruefe-api-oberflaeche.sh` | reproduziert die API-Messung |
| `spikes/S1/ergebnisse/` | Rohausgaben aller Läufe |
| `spikes/S1/adr-entwurf-GATE-1.md` | ADR-Entwurf für GATE-1 |

Reproduktion:
```
cd spikes/S1/desc-auth  && cargo run --release          # K3, offline
bash spikes/S1/pruefe-api-oberflaeche.sh                # API-Oberflaeche
cd spikes/S1/netcheck   && rustc -O -o netcheck.exe src/main.rs && ./netcheck.exe
cd spikes/S1/arti-probe && cargo run --release --bin bootstrap-timing -- 12 240
```

---

## 7. Risikoregister-Rückmeldung

`spec/phase0-spikeplan.md` §6, R-1 („Arti-Client-Auth nicht produktionsreif",
W mittel / A hoch, Frühindikator „S1-Zwischenstand Woche 2"):

**Wahrscheinlichkeit auf niedrig-mittel gesenkt.** Die Kryptografie ist
wirksam und die Service-Seite ist nicht als experimentell markiert. Der
verbleibende Anteil des Risikos verlagert sich von „funktioniert nicht" zu
„API-Stabilität und Revocation-Semantik" (Auflagen A2 und A3). C-tor bleibt als
Interim-Maßnahme dokumentiert, wird aber nicht aktiviert.
