# ADR-15: Tor-Stack für Phase 1 — Arti mit erzwungener Client-Auth

> **Entwurf aus Spike S1.** Noch nicht in `adr/` abgelegt. Nummer 15 ist
> vorgeschlagen (ADR-01 bis ADR-14 sind in `spec/engineering-setup.md` §1
> vergeben, `adr/` ist bislang leer). Vorlage: `adr/README.md`.

- **Status:** vorgeschlagen
- **Datum:** 2026-07-25
- **Betrifft:** `core/vault-transport` (tor/), `spec/gesamtkonzept.md` §2.2 und
  §2.5, `spec/protokoll-spec.md` (Revocation), `spec/threat-model.md` §4/A3 und
  §4/A4, ADR-02, ADR-03
- **Löst Gate:** GATE-1

## Kontext

`spec/phase0-spikeplan.md` §4 verlangt für GATE-1 die schriftliche Festlegung
des Tor-Stacks auf Basis von S1. `spec/gesamtkonzept.md` §2.5 gibt die Richtung
vor:

> „**Tor-Stack:** Zielarchitektur **Arti** (Rust, memory-safe). Bis dessen
> Onion-Client-Auth produktionsreif ist, **C-tor in Prozessisolation mit
> seccomp-Sandbox**."

Client-Auth ist nicht optional. `spec/gesamtkonzept.md` §2.2:

> „**Tor v3 Client Authorization ist Pflicht.** Der Descriptor ist an die
> Schlüssel der berechtigten Kontakte verschlüsselt. Wer keine Credential
> besitzt, kann den Dienst weder finden noch seine Existenz bestätigen noch ihn
> proben."

`spec/threat-model.md` §4/A3 bewertet die daraus folgenden Restrisiken mit ○ und
begründet das ausdrücklich mit „Tor v3 Client Authorization (Pflicht)".

Datengrundlage ist Spike S1 (`spikes/S1/BERICHT.md`, arti 0.44.0, gemessen am
2026-07-25). Kernbefunde:

- 1000 von 1000 unberechtigten Descriptor-Entschlüsselungen scheitern (100 %).
  8 von 8 autorisierten gelingen.
- Ein HSDir kann am Descriptor nicht erkennen, ob Client-Auth aktiv ist:
  gleiche Schlüsselwörter, gleiche Länge (14.427 Bytes) mit und ohne.
- Bis 80 autorisierte Clients ist die Descriptor-Größe konstant; die
  Kontaktanzahl leakt nicht über das Volumen.
- Service-seitig ist Restricted Discovery in arti 0.44.0 **nicht** als
  experimentell markiert; `launch_onion_service` ebenfalls nicht.
- Client-seitig liegt die Schlüsselverwaltung
  (`generate/insert/rotate/remove_service_discovery_key`) hinter
  `experimental-api` — per Compilerfehler belegt.
- Arti dokumentiert ausdrücklich
  (`tor-hsservice-0.44.0/src/config/restricted_discovery.rs:50–62`), dass das
  Entfernen eines Clients aus der Liste **keine** Zugangsentziehung garantiert,
  weil Intro-Points nicht rotiert werden.
- Onion-Aufbauzeiten (< 20 s p50, < 60 s p95) und Android/Linux-Betrieb konnten
  nicht gemessen werden. Es liegt kein Beleg gegen Arti vor, aber auch keiner
  dafür.

## Entscheidung

1. **Arti ist der Tor-Stack für Phase 1.** C-tor wird nicht eingebettet.
2. **Restricted Discovery (v3 Client Authorization) ist in jeder
   Kompartiment-Konfiguration aktiv.** Ein Kompartiment ohne aktive Client-Auth
   wird nicht gestartet. Es gibt keine Konfigurationsoption, die das abschaltet.
3. **Revocation stützt sich nicht auf die Clientliste allein.** Jede Entfernung
   eines Kontakts löst zusätzlich eine erzwungene Intro-Point-Rotation des
   betroffenen Kompartiments aus. Ohne bestätigte Rotation gilt eine Revocation
   als nicht wirksam und wird der Nutzerin als „läuft" angezeigt.
4. **Der Zugriff auf Arti läuft ausschließlich über ein eigenes Adaptermodul**
   in `core/vault-transport/tor/`. Alles, was in arti hinter `experimental-api`
   oder `__is_experimental` liegt, wird dort gekapselt und durch Vertragstests
   abgesichert, die bei einem Arti-Upgrade brechen müssen, statt still das
   Verhalten zu ändern.
5. **Ein Kompartiment ohne autorisierte Kontakte wird nicht publiziert.** Der
   Zustand wird in Vault abgefangen, bevor er Arti erreicht (Arti erzeugt dort
   einen internen Fehler).
6. **Obergrenze 80 Kontakte je Kompartiment.**
7. **GATE-1 gilt bis zum Nachweis von K1 und K2 auf Android und Linux als
   vorläufig.** Der Nachweis ist Voraussetzung für den Abschluss von Phase 0
   (`spec/phase0-spikeplan.md` §7). Bleibt er aus, wird diese Entscheidung
   erneut aufgerufen — dann mit dem Fallback C-tor sandboxed, nicht mit einem
   Verzicht auf Client-Auth.

## Alternativen

- **C-tor als Subprozess mit seccomp-Sandbox.** Der in §2.5 vorgesehene
  Interim. Verworfen für Phase 1, weil kein Befund vorliegt, der Arti
  disqualifiziert, und weil C-tor eine zweite Prozess- und Sprachgrenze,
  eine Control-Port-Schnittstelle und plattformabhängige Sandboxes
  (seccomp gibt es unter Windows nicht) einführt. Bleibt als benannter
  Rückfallweg bestehen; nicht geprüft (S1 §4, Punkt 5).
- **Arti ohne Client-Auth starten und später nachrüsten.** Nicht zulässig:
  `spec/phase0-spikeplan.md` §2 schließt das ausdrücklich aus, und
  `spec/threat-model.md` §4/A3 verliert damit seine Begründung.
- **Eigene Descriptor-Verschlüsselung oberhalb von Tor.** Verstößt gegen
  „keine eigenen Kryptoprimitive" (`CLAUDE.md`) und würde den
  HSDir-Enumerationsschutz nicht ersetzen.
- Ansätze aus `spec/gesamtkonzept.md` Anhang A werden hier nicht erneut
  aufgerollt.

## Auswirkung auf das Threat Model

**Pflichtfeld.**

- **A3 (Tor-Infrastruktur-Angreifer) gewinnt nichts.** Die beiden mit ○
  bewerteten Zeilen „HSDir-Enumeration" und „Präsenz-Probing durch Fremde"
  sind durch S1 messtechnisch gestützt (1000/1000 Fehlschläge; Descriptor
  ununterscheidbar). Die Zeile „Rückschluss auf Kontaktanzahl aus
  Descriptor-Volumen" ist gemessen bis 80 Kontakte je Kompartiment gehalten —
  die Obergrenze aus Entscheidung 6 macht die ○-Bewertung überprüfbar statt
  angenommen.
- **A4 (übernommener Kontakt): neues, benanntes Restrisiko.** Die Zeile
  „Weiterbestehender Zugriff nach Enttarnung — Ein-Schritt-Revocation" war mit
  ○ bewertet. Arti garantiert das nicht von sich aus: ohne Intro-Point-Rotation
  behält ein entzogener Kontakt einen nutzbaren Pfad. Entscheidung 3 stellt die
  Eigenschaft wieder her, verschiebt sie aber von „von der Plattform garantiert"
  zu „von Vault erzwungen". Bis S3 die Wirksamkeit misst, ist die Bewertung
  **◐ statt ○**. Das ist die einzige Verschlechterung gegenüber dem
  veröffentlichten Threat Model und muss dort nachgezogen werden.
- **A6 (Lieferkette): Angriffsfläche benannt.** Der Arti-Graph umfasst 414
  Crates, darunter drei C-basierte (`libsqlite3-sys`, `liblzma-sys`,
  `zstd-sys`); `libsqlite3-sys` ist über `tor-dirmgr` nicht abwählbar. Die
  Aussage „Rust, memory-safe" aus §2.5 gilt für den Protokollkern, nicht für den
  Gesamtgraphen. `cargo-vet`/`cargo-deny` müssen diese Fläche abdecken
  (`spec/gesamtkonzept.md` §2.11). Restrisiko unverändert ◐, aber präziser.
- **A1/A2:** unverändert. Snowflake/meek (§2.5) wurde in S1 nicht geprüft und
  bleibt offen.
- **Anonymitätsset (§5 Threat Model, `spec/gesamtkonzept.md` §2.9):**
  unverändert. Client-Auth ist für alle Nutzer gleich aktiv, es entsteht keine
  wählbare Variante und damit keine Partitionierung.

## Auswirkung auf den Prioritätsstack

- **Priorität 1 (Anonymität):** gestärkt. Client-Auth bleibt Pflicht und ist
  messtechnisch belegt. Keine Abschwächung.
- **Priorität 2 (Serverlosigkeit):** nicht berührt. Arti benötigt keinen
  eigenen Server; das Tor-Netz ist bereits als nicht vertrauenswürdig
  modelliert (`spec/threat-model.md` §1.1).
- **Priorität 3:** belastet. Die Kapselung experimenteller Arti-APIs, die
  erzwungene Intro-Point-Rotation und die Kontaktobergrenze kosten Aufwand und
  Komfort. Das ist laut Prioritätsstack ausdrücklich opferbar.

Keine der beiden oberen Prioritäten wird verletzt; die Entscheidung ist
zulässig.

## Konsequenzen

**Leichter:**
- Ein Prozess, eine Sprache, keine Control-Port-Schnittstelle, keine
  plattformabhängige Sandbox.
- `#![forbid(unsafe_code)]` bleibt im Transport-Crate haltbar, weil keine
  FFI-Bindung zu C-tor entsteht.
- Reproduzierbare Builds (E3) werden einfacher als mit einem mitgelieferten
  C-tor-Binary.

**Schwerer:**
- Abhängigkeit von `experimental-api` ohne Semver-Zusage; jedes Arti-Upgrade
  braucht einen bewussten Durchgang durch das Adaptermodul.
- Revocation muss selbst gebaut und in S3 gemessen werden.
- Android-Build braucht NDK, `rustls` statt `native-tls` und eine explizite
  `CryptoProvider`-Installation.

**Folgearbeiten:**
1. K1/K2 auf Android und Linux nachmessen; GATE-1 danach von „vorläufig" auf
   „akzeptiert" heben oder die Entscheidung neu aufrufen.
2. `spec/protokoll-spec.md` um die erzwungene Intro-Point-Rotation bei
   Revocation ergänzen; S3 misst deren Wirksamkeit.
3. `spec/threat-model.md` §4/A4: „Weiterbestehender Zugriff nach Enttarnung"
   auf ◐ setzen, bis S3 die Rotation belegt.
4. `spec/phase0-spikeplan.md` §2: Definition von „Onion-Aufbau" präzisieren
   (Dienst erreichbar vs. Client verbunden).
5. Adaptermodul `core/vault-transport/tor/` mit Vertragstests anlegen.
6. Snowflake/meek (§2.5) als eigener Prüfpunkt einplanen — in S1 nicht geprüft.
