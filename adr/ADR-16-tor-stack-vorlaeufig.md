# ADR-16: Tor-Stack — vorläufiger Stand nach Spike S1 (GATE-1 offen)

- **Status:** **VORLÄUFIG** — dies ist ausdrücklich **keine** endgültige
  Stack-Festlegung. GATE-1 bleibt offen.
- **Datum:** 2026-07-25
- **Betrifft:** `core/vault-transport` (tor/), `spec/gesamtkonzept.md` §2.2 und
  §2.5, `spec/threat-model.md` §4/A3, ADR-02, ADR-03
- **Löst Gate:** GATE-1 — **nicht gelöst**, Zwischenstand festgehalten
- **Gate-Zuordnung:** **GATE-1 → ADR-16** (dieses Dokument). Die Nummerierung
  folgt der Reihenfolge der ADR-Erstellung, nicht der Gate-Nummer; ADR-15
  behandelt die Intro-Point-Rotation, GATE-2 liegt in ADR-17.

## Kontext

`spec/phase0-spikeplan.md` §4 verlangt für GATE-1 die schriftliche Festlegung
des Tor-Stacks (Arti oder C-tor sandboxed) auf Basis von Spike S1. S1 ist
durchgeführt (`spikes/S1/`), konnte aber nur **eines von drei**
Erfolgskriterien messen. Dieser ADR hält fest, was belegt ist und was nicht,
damit die offene Entscheidung nicht stillschweigend durch Gewohnheit
vorweggenommen wird.

### Was gemessen und belegt ist

**K3 — nicht-autorisierter Descriptor-Abruf scheitert zu 100 %: erfüllt.**

| Messung | Ergebnis |
|---|---|
| Abruf mit fremdem Key (frisch je Versuch) | 0 von 500 erfolgreich |
| Abruf ohne Key (HSDir/Enumerator) | 0 von 500 erfolgreich |
| **Summe** | **1000/1000 abgewiesen = 100,0000 %** |
| Kontrolle: autorisierter Abruf | 8 von 8 erfolgreich |
| Kontrolle: ohne Client-Auth | lesbar (Testaufbau validiert) |

Ergänzend: Descriptor mit und ohne Client-Auth haben **identische Länge
(14.427 B)** und identische HSDir-sichtbare Keywords — ein HSDir kann nicht
einmal erkennen, *dass* Client-Auth aktiv ist. Die Größe bleibt bis 80
autorisierte Clients konstant; die Kontaktanzahl leakt nicht über das
Descriptor-Volumen, wie `spec/gesamtkonzept.md` §2.2 es verlangt.

### Was nicht gemessen ist

**K1 — Client-Auth auf allen Zielplattformen: ungemessen.**
Windows x86_64 baut und startet. Android aarch64 bricht nach 89,8 s in `cc-rs`
ab (kein NDK). Für **Linux und iOS existiert kein Host** in der
Spike-Umgebung. Damit ist die Kernaussage für drei der vier Plattformen offen.

**K2 — Onion-Aufbau < 20 s (p50) / < 60 s (p95): nicht messbar, keine Zahl.**
Belegkette bis zum Abbruch: TCP zu Dirauths 6/8 und zu Fallback-Dirs 11/12
erreichbar, Arti-Link-Handshake 3/3 erfolgreich, Einhop-Circuits gebaut —
der Konsens-Download liefert jedoch nichts, nach 60 s `DESTROY … too dirty or
old`. Zwei Läufe (> 15 min, > 8 min) ohne Bootstrap-Abschluss.

**Der gesamte Fallback-Zweig ist ungeprüft.** Methodenschritt 4 der Spec
(C-tor als Subprozess mit seccomp-Sandbox) wurde nicht ausgeführt: kein
`tor`-Binary, und seccomp existiert unter Windows nicht. Ebenso ungeprüft:
eigener HSDir-Beobachter (Methodenschritt 3), Speicher- und Startzeiten,
Snowflake/meek.

## Entscheidung

**Es wird kein Tor-Stack festgelegt.** GATE-1 bleibt offen bis zum Nachzug von
S1 auf Linux und Android.

Vorläufig gilt:

1. **Arti bleibt Zielkandidat** entsprechend `spec/gesamtkonzept.md` §2.5
   („Zielarchitektur Arti"). Der für das Sicherheitsversprechen tragende Teil —
   der Descriptor-Schutz — ist gemessen und trägt. Es liegt **kein Befund vor,
   der Arti disqualifiziert**, aber auch keiner, der K1/K2 belegt.
2. **C-tor in Prozessisolation mit seccomp-Sandbox bleibt der benannte
   Fallback** nach §2.5 und ist beim Nachzug von S1 mitzuprüfen, statt ihn
   durch Nichtbefassung auszuscheiden.
3. **Das Abbruchkriterium aus `spec/phase0-spikeplan.md` §4 liegt nicht vor.**
   Es lautet „Client-Auth auf keiner Plattform" — der Descriptor-Schutz
   funktioniert nachweislich. Kein Projektstopp.
4. **Ein Betrieb ohne Client-Auth ist und bleibt kein zulässiger Fallback**
   (§2, S1: „stattdessen Projektstart verschieben"). Diese Festlegung gilt
   unabhängig vom Stack und ist nicht Gegenstand der offenen Entscheidung.
5. **Arti-Zugriff nur über ein eigenes Adaptermodul** in
   `core/vault-transport/tor/`. Was in Arti hinter `experimental-api` liegt —
   S1 hat das für die clientseitige Schlüsselverwaltung per Compilerfehler
   belegt — wird dort gekapselt und mit Vertragstests abgesichert, die bei
   einem Upgrade brechen müssen, statt still das Verhalten zu ändern. Diese
   Auflage gilt für jeden Stack, der experimentelle APIs mitbringt.
6. **Ein Kompartiment ohne autorisierte Kontakte wird nicht publiziert.** S1
   hat einen Defekt gemessen: Client-Auth mit 0 Clients erzeugt in Arti
   `Bug/BadApiUsage`, obwohl die API-Doku `Some(&[])` als zulässig beschreibt.
   Der Leerfall wird in Vault abgefangen, bevor er die Bibliothek erreicht.
7. **Vorläufige Obergrenze 80 Kontakte je Kompartiment**, abgeleitet aus der
   gemessenen Größenkonstanz. Der Wert ist eine Messgrenze, keine
   Designentscheidung, und ist bei erweiterter Messung anzupassen.

## Alternativen

- **Jetzt auf Arti festlegen.** Verworfen: zwei von drei Kriterien sind
  ungemessen, und für drei von vier Zielplattformen liegt überhaupt kein
  Befund vor. Eine Festlegung wäre nicht durch Daten gedeckt und würde die
  Prüfung von C-tor faktisch beenden.
- **Jetzt auf C-tor festlegen.** Verworfen: noch schlechter belegt — der
  Fallback-Zweig wurde gar nicht ausgeführt.
- **GATE-1 formlos offen lassen ohne ADR.** Verworfen: `CLAUDE.md` und
  `adr/README.md` verlangen schriftliche Fixierung; ein Zwischenstand ohne
  Dokument wird stillschweigend zur Gewohnheitsentscheidung.

## Auswirkung auf das Threat Model

**Pflichtfeld.**

- **A3 (Tor-Infrastruktur-Angreifer):** Die mit ○ bewerteten Zeilen
  „HSDir-Enumeration" und „Präsenz-Probing durch Fremde" sind durch S1
  erstmals **messtechnisch gestützt** statt nur angenommen (1000/1000;
  Descriptor ununterscheidbar). Keine Änderung der Bewertung, aber härtere
  Grundlage.
- **A4, Zeile „Weiterbestehender Zugriff nach Enttarnung":** von diesem ADR
  nicht behandelt. Der zugehörige Befund und die Konsequenz stehen in
  **ADR-15**; die dortige Herabstufung auf ◐ bis zum Nachweis durch S3 gilt.
- **A6 (Lieferkette):** präzisiert, Bewertung unverändert ◐. Der Arti-Graph
  umfasst 414 Crates, darunter drei C-basierte `-sys`-Crates; `libsqlite3-sys`
  ist über `tor-dirmgr` nicht abwählbar. Die Zusage „Rust, memory-safe" aus
  §2.5 gilt für den Protokollkern, nicht für den Gesamtgraphen. `cargo-deny`
  und `cargo-vet` (Gates G-3/G-4) müssen diese Fläche abdecken.
- **Anonymitätsset (§2.9):** unberührt. Client-Auth ist für alle Nutzer gleich
  aktiv; es entsteht keine wählbare Variante.

## Auswirkung auf den Prioritätsstack

- **Priorität 1:** nicht berührt — es wird nichts abgeschwächt, nur nichts
  entschieden.
- **Priorität 2:** nicht berührt.
- **Priorität 3:** belastet — die offene Entscheidung hält den Transportpfad
  und damit Sprint 0 #5 auf.

## Konsequenzen

**Leichter:** Der Descriptor-Schutz muss nicht erneut in Frage gestellt werden;
das Adaptermodul kann unabhängig vom Stack entworfen werden.

**Schwerer:** Sprint 0 #5 („Onion-Service hochfahren, Client-Auth setzen —
Ergebnis aus GATE-1") ist blockiert. `spec/engineering-setup.md` §7 nennt
GATE-1 bis GATE-6 als Bedingung der Startfreigabe für Phase 1; diese ist damit
nicht erreicht.

**Folgearbeiten:**
1. S1 auf **Linux** (Host) und **Android** (NDK) nachziehen; K1 und K2 messen.
   Dabei C-tor sandboxed nach Methodenschritt 4 mitprüfen.
2. Eigenen HSDir-Beobachter aufsetzen (Methodenschritt 3, z. B. via chutney) —
   K3 ist bislang offline gegen `tor-netdoc` belegt, nicht im laufenden Netz.
3. Danach diesen ADR ersetzen: entweder Festlegung auf Arti oder Rückfall auf
   C-tor sandboxed. Ein Verzicht auf Client-Auth steht nicht zur Wahl.
4. `spec/phase0-spikeplan.md` §2 präzisieren: „Onion-Aufbau" ist als
   Dienst-erreichbar oder als Client-verbunden zu definieren — beide Lesarten
   messen Verschiedenes. **Offener Punkt, noch nicht eingearbeitet.**
