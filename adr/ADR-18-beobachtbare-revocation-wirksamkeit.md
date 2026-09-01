# ADR-18: Beobachtbare Wirksamkeit der Revocation

- **Status:** **ENTWURF — wartet auf Freigabe.** Nichts hieran ist entschieden.
- **Datum:** 2026-07-26
- **Betrifft:** `core/vault-transport` (tor/), `core/vault-identity` (credential),
  `spec/protokoll-spec.md` §11, `spec/threat-model.md` §4/A4; ADR-15, ADR-16
- **Löst Gate:** — (Folgeentscheidung aus ADR-15, Datengrundlage Spike S3)

## Kontext

`spec/protokoll-spec.md` §11 verlangt seit ADR-15:

> „Eine Revocation gilt erst als wirksam, wenn Rotation und
> Descriptor-Neuveröffentlichung bestätigt sind. Bis dahin zeigt die UI
> ‚Trennung läuft', nicht ‚getrennt'."

Damit ist „bestätigt" ein normativer Begriff — ohne dass festgelegt wäre, wie
eine Bestätigung zustande kommt. Spike S3 hat gemessen, dass es dafür in der
Bibliothek **keinen Beobachtungspunkt gibt**:

| Hebel | Vorhanden? | Beleg |
|---|---|---|
| `reconfigure` | ja | Compilerprüfung, S3 |
| `pause()` | **nein** | `E0599`, S3 |
| `rotate_intro_points()` | **nein** | `E0599`, S3 |
| Rotationsbestätigung aus `OnionServiceStatus` | **nein** | `E0599`, S3 |
| Dienst-Neustart rotiert? | **nein** | `ipt_mgr/persist.rs:159`, `IptExpectExistingKeys` |

Weitere Befunde aus S3, die den Handlungsdruck bestimmen:

- Ohne erzwungene Rotation zieht Arti die Retirement-Zeit zufällig aus
  `[hs_intro_min_lifetime, hs_intro_max_lifetime]` der Konsens-Parameter
  (`ipt_mgr.rs:1627–1641`). Mit den Tor-Defaults 18–24 h bliebe der Zugang
  eines Revozierten **18 bis ~27 h** bestehen — das **216-fache** des
  S3-Kriteriums von 5 Minuten.
- Der Revozierte wird am **neuen** Descriptor zuverlässig abgewiesen
  (500/500), liest aber seinen **zwischengespeicherten alten** Descriptor
  weiter: drei Intro-Point-Schlüssel bleiben lesbar, `descriptor-lifetime`
  180 min.
- Der lokale Anteil einer Revocation ist vernachlässigbar (p95 0,855 ms; bei
  80 Kontakten 3,675 ms = 0,0013 % des 300-s-Budgets). Das Kriterium
  entscheidet sich **vollständig** am Netzanteil.
- Die Modul-Dokumentation weist darauf hin, dass der Republish dem gerade
  Revozierten die **neuen** Intro-Points aushändigen kann — ein
  Reihenfolgeproblem.

## Vorgeschlagene Entscheidung

> Alles in diesem Abschnitt ist **Vorschlag**, nicht Beschluss.

**Vault verifiziert die Wirksamkeit einer Revocation selbst und beobachtbar,
statt sie der Transportschicht zu glauben.** Ablauf:

1. Credential entziehen, `intro_point_epoch += 1`, Rotation auslösen,
   Descriptor neu veröffentlichen (unverändert §11 Schritte 1–3).
2. **Kontroll-Abruf durch den eigenen Client:** Vault ruft den eigenen
   Descriptor über einen unabhängigen Circuit ab und prüft
   (a) der neue Descriptor ist abrufbar und trägt **rotierte**
   Intro-Points — Schnittmenge mit der alten Menge leer;
   (b) die **alten** Intro-Points antworten nicht mehr.
3. Erst wenn (a) **und** (b) erfüllt sind, gilt die Revocation als wirksam
   und die UI zeigt „getrennt".

Die Analogie ist das E2E-ACK aus §9.4: Ein Zustand wird erst behauptet, wenn
er belegt ist — nicht, wenn er angefordert wurde.

## Offene Fragen — ausdrücklich nicht entschieden

1. **Schwellwerte.** Wie oft und über wie viele unabhängige Circuits muss
   (a) bzw. (b) bestätigt werden, bevor „wirksam" gilt? Ein einzelner
   erfolgreicher Abruf beweist wenig, wenn der Angreifer den Circuit
   kontrolliert.
2. **Timeout-Verhalten.** Was passiert, wenn die Bestätigung ausbleibt —
   unbegrenzt „Trennung läuft" anzeigen, oder nach einer Frist auf einen
   Fehlerzustand wechseln? Ein Dauerzustand „läuft" ist für die Nutzerin
   nicht handlungsleitend.
3. **Teilbestätigung.** (a) erfüllt, (b) nicht: Der neue Descriptor ist
   sauber, aber ein alter Intro-Point antwortet noch. Gilt das als wirksam,
   als unwirksam, oder als eigener dritter Zustand?
4. **Prüfung durch den eigenen Client als Signal.** Der Kontroll-Abruf ist
   selbst Netzverkehr mit einem charakteristischen Muster (Abruf des eigenen
   Descriptors unmittelbar nach einer Republikation). Verrät er einem
   HSDir-Beobachter, dass gerade eine Revocation stattgefunden hat? Das wäre
   ein neues Präsenz-/Ereignissignal und berührt §2.9 sowie GATE-3.
5. **Reihenfolge Rotation ↔ Republish.** S3 nennt das Risiko, dass der
   Republish dem Revozierten die neuen Intro-Points aushändigt.
   TeardownFirst oder MakeBeforeBreak? Beides hat einen Preis: Ersteres eine
   Erreichbarkeitslücke für die verbliebenen Kontakte, Letzteres ein Fenster
   für den Revozierten.
6. **Eigener Spike nötig?** Die Frage lässt sich ohne laufendes Tor nicht
   messen. S3 ist genau daran blockiert. Braucht es einen Spike S3b für die
   Bestätigungsmechanik, oder ist sie Teil von S3, sobald ein Testnetz steht?
7. **Zustand über Neustarts.** Eine unbestätigte Revocation muss einen
   App-Neustart überleben und danach weiterlaufen — sonst bleibt sie stumm
   liegen. Wo wird dieser Zustand gehalten (`vault-storage`)?

## Auswirkung auf das Threat Model

**Pflichtfeld — hier als Vorschau, da die Entscheidung offen ist.**

- **A4, „Weiterbestehender Zugriff nach Enttarnung":** derzeit ◐ (ADR-15).
  Mit einer belegten Bestätigung wäre ○ wieder begründbar — aber erst, wenn
  S3 die Latenz gemessen hat. Ohne Messung bleibt ◐, unabhängig von diesem
  ADR.
- **A3 (Tor-Infrastruktur):** offene Frage 4 kann ein **neues** Restrisiko
  erzeugen (Ereignissignal an HSDir-Beobachter). Vor einer Entscheidung zu
  klären.
- **Anonymitätsset (§2.9):** unberührt, solange die Bestätigungsmechanik für
  alle Nutzer gleich und nicht konfigurierbar ist.

## Auswirkung auf den Prioritätsstack

- **Priorität 1:** gestärkt, sofern offene Frage 4 sauber gelöst wird —
  andernfalls verschiebt sich Risiko von A4 nach A3.
- **Priorität 2:** unberührt; die Prüfung läuft gegen das eigene Onion und
  braucht keinen Dritten.
- **Priorität 3:** belastet — zusätzliche Circuits, längere Wartezeit bis
  „getrennt", mehr Zustand.

## Konsequenzen

**Leichter:** „Wirksam" wird eine überprüfbare Eigenschaft statt einer
Behauptung; S3 bekommt einen klar definierten Messpunkt.

**Schwerer:** Vault muss den eigenen Descriptor abrufen und Intro-Points
vergleichen können — Funktionalität, die es bisher nicht braucht.

**Folgearbeiten (falls freigegeben):** §11 um die Bestätigungsmechanik
ergänzen · Zustandsmodell für laufende Revocations in `vault-storage` ·
S3 um die Messung der Bestätigungslatenz erweitern · offene Frage 4 an
GATE-3 übergeben.
