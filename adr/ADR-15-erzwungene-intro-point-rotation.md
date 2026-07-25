# ADR-15: Erzwungene Intro-Point-Rotation bei jeder Revocation

- **Status:** akzeptiert
- **Datum:** 2026-07-25
- **Betrifft:** `core/vault-transport` (tor/), `core/vault-identity` (credential),
  `spec/gesamtkonzept.md` §2.2, `spec/protokoll-spec.md` §11,
  `spec/threat-model.md` §4/A4, ADR-03
- **Löst Gate:** — (Voraussetzung für Spike S3; unabhängig von GATE-1)

## Kontext

`spec/gesamtkonzept.md` §2.2 verspricht granulare Revocation:

> „**Jeder Kontakt erhält eine eigene Client-Auth-Credential** innerhalb seines
> Kompartiments. Damit ist **granulare Revocation** möglich: Ein feindlich
> gewordener Kontakt wird einzeln entfernt, alle anderen bleiben unberührt,
> keine Neu-Verifikation nötig."

`spec/threat-model.md` §4/A4 bewertet die Zeile „Weiterbestehender Zugriff nach
Enttarnung" mit **○ vernachlässigbar** und nennt als Gegenmaßnahme wörtlich
„**Ein-Schritt-Revocation**: Credential + **Intro-Point-Rotation** + Mesh-Key +
Session-Purge". Die Rotation ist im Threat Model also bereits vorausgesetzt.

Spike S1 hat belegt, dass die Tor-Implementierung sie nicht von sich aus
liefert. `tor-hsservice 0.44.0`, `src/config/restricted_discovery.rs:50–62`:

> „Removing a previously authorized client from `static_keys` or `key_dirs`
> does **not** guarantee its access will be revoked. This is because the client
> might still be able to reach your service via its current introduction points
> (the introduction points are not rotated when the authorized clients change).
> […] **Restricted discovery mode is a DoS resistance mechanism, _not_ a
> substitute for conventional access control.**"

Das Zitat wurde im Quelltext der installierten Crate-Version nachgeprüft, nicht
aus Dokumentation übernommen. Der Befund ist **stack-unabhängig**: Er folgt aus
der Funktionsweise von Onion-Service-Descriptors und Introduction Points, nicht
aus einer Eigenheit von Arti. Ein Wechsel zu C-tor beseitigt ihn nicht
automatisch; C-tor wurde dazu nicht geprüft.

Ohne Gegenmaßnahme entsteht eine Lücke zwischen dem Entzug der Credential und
dem tatsächlichen Zugriffsverlust: Ein revozierter Kontakt behält über die
bestehenden Introduction Points einen nutzbaren Pfad. Genau dieser Fall — der
übernommene, gerade enttarnte Kontakt — ist der Anlass für die Revocation.

## Entscheidung

1. **Vault implementiert die Intro-Point-Rotation selbst.** Sie ist Teil der
   Revocation, nicht eine Eigenschaft, die von der Transportschicht erwartet
   wird. Die Entscheidung gilt **unabhängig vom gewählten Tor-Stack** und
   überdauert GATE-1.
2. Jede Revocation eines Kontakts löst zwingend aus:
   Entzug der Client-Auth-Credential · Erhöhung von `intro_point_epoch` des
   betroffenen Kompartiments (`spec/protokoll-spec.md` §3) · erzwungene
   Rotation der Introduction Points · Neuveröffentlichung des Descriptors ·
   Löschen von `mesh_key` · Session-Purge.
3. **Eine Revocation gilt erst als wirksam, wenn die Rotation bestätigt ist.**
   Bis dahin zeigt die UI „läuft" und nicht „getrennt". Eine Falschmeldung an
   dieser Stelle wäre dieselbe Klasse von Unehrlichkeit wie ein `delivered`
   ohne E2E-ACK (`CLAUDE.md`).
4. **Spike S3 misst die tatsächliche Wirksamkeit und Latenz.** Erfolgskriterium
   bleibt `spec/phase0-spikeplan.md` §3: Verbindungsverlust des Revozierten in
   < 5 min (p95).
5. Solange S3 den Nachweis nicht erbracht hat, ist die Eigenschaft **behauptet,
   nicht belegt** — mit der Folge unter „Auswirkung auf das Threat Model".

## Alternativen

- **Auf die Clientliste allein vertrauen.** Verworfen: von der Implementierung
  ausdrücklich als unzureichend dokumentiert. Das Versprechen aus §2.2 wäre
  nicht haltbar, und die ○-Bewertung von A4 verlöre ihre Grundlage.
- **Kompartiment nach Revocation komplett neu aufsetzen** (neuer OSK, neue
  Onion-Adresse). Wirksam, aber es zwingt **alle** verbliebenen Kontakte zur
  Neu-Verifikation — genau das, was §2.2 ausschließt („keine Neu-Verifikation
  nötig"). Bleibt als Notfallweg bei Verdacht auf Kompromittierung des
  Kompartiment-Schlüssels, nicht als Regelweg.
- **Auf C-tor wechseln in der Annahme, es rotiere.** Verworfen als Begründung:
  ungeprüft, und der Befund ist nicht Arti-spezifisch. Ein Stackwechsel darf
  nicht mit einer unbelegten Hoffnung begründet werden.
- **Revocation-Versprechen in §2.2 abschwächen.** Verworfen: verletzt
  Priorität 1 des Prioritätsstacks.

## Auswirkung auf das Threat Model

**Pflichtfeld.**

- **A4 (übernommener Kontakt), Zeile „Weiterbestehender Zugriff nach
  Enttarnung": heute ○, künftig ◐ bis zum Nachweis.** Die Eigenschaft wandert
  von „durch die Plattform garantiert" nach „von Vault erzwungen". Erzwungenes
  Verhalten ist so gut wie sein Nachweis, deshalb gilt: **○ nur, wenn S3 die
  Wirksamkeit der Rotation belegt — bis dahin ◐.** Das ist die einzige
  Verschlechterung gegenüber dem veröffentlichten Threat Model und muss dort
  nachgezogen werden, sobald dieser ADR wirksam ist.
- **A4/G3 (Präsenz-Probing als autorisierter Kontakt, ◐):** unverändert.
- **A3 (Tor-Infrastruktur-Angreifer):** unverändert. Die Rotation erhöht die
  Zahl der Descriptor-Neuveröffentlichungen; das Publikations-Timing ist
  Gegenstand von S4 und darf kein neues Muster erzeugen — als Prüfpunkt an S4
  übergeben.
- **Anonymitätsset (`spec/gesamtkonzept.md` §2.9):** unberührt. Die Rotation
  läuft bei allen Nutzern gleich und ist nicht konfigurierbar.

## Auswirkung auf den Prioritätsstack

- **Priorität 1 (Anonymität und Datenschutz):** gestärkt — das Versprechen aus
  §2.2 wird eingelöst statt vorausgesetzt.
- **Priorität 2 (Serverlosigkeit):** nicht berührt.
- **Priorität 3:** belastet — Mehraufwand in Implementierung und Testbarkeit,
  kurzzeitige Erreichbarkeitslücke des eigenen Dienstes während der Rotation.
  Laut Prioritätsstack ausdrücklich opferbar.

Keine der beiden oberen Prioritäten wird verletzt; die Entscheidung ist zulässig.

## Konsequenzen

**Leichter:** Die Revocation-Semantik ist an einer Stelle definiert und nicht
über Transport-Implementierungen verteilt; ein späterer Stackwechsel ändert sie
nicht.

**Schwerer:** Vault muss Introduction Points aktiv steuern statt sie der
Bibliothek zu überlassen. Auf der Arti-Client-Seite liegen Teile der
Schlüsselverwaltung hinter `experimental-api` (S1) und brauchen Kapselung.

**Folgearbeiten:**
1. Spike S3 durchführen — durch diesen Befund von 🟠 faktisch auf kritisch
   hochgestuft, weil er entscheidet, ob das Versprechen aus §2.2 einlösbar ist.
2. `spec/protokoll-spec.md` §11 um die erzwungene Rotation und die Bedingung
   „wirksam erst nach bestätigter Rotation" ergänzen. **Offener Punkt, noch
   nicht eingearbeitet.**
3. `spec/threat-model.md` §4/A4 auf ◐ setzen, bis S3 den Nachweis erbringt.
   **Offener Punkt, noch nicht eingearbeitet.**
4. Publikations-Timing der Rotation als Prüfpunkt in S4 aufnehmen.
