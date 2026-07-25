# ADR-Entwurf zu GATE-3 — Parameter des einheitlichen Netzprofils

> **Dies ist ein Entwurf, kein ADR.** Er liegt bewusst unter `spikes/S5/` und
> nicht unter `adr/`. Aufgenommen wird er erst, wenn S4 und S5 gemessen sind und
> alle mit `<offen>` markierten Felder mit **gemessenen** Werten gefüllt sind.
> Die Nummer wird bei der Aufnahme vergeben (nächste freie nach ADR-14; wenn
> GATE-1 und GATE-2 vorangehen, wäre das ADR-17).
>
> Vorlage: `adr/README.md`. Bis zur Aufnahme gilt: **keine Werte vorwegnehmen.**

---

# ADR-<NN>: Parameter des einheitlichen Netzprofils

- **Status:** Entwurf — nicht entscheidungsreif (S5 offen, siehe `spikes/S5/BERICHT.md`)
- **Datum:** <offen — Datum der Aufnahme>
- **Betrifft:** `vault-transport` (tor/, mesh/), `vault-delivery` (Sync-Fenster), `privacy`/Shaping; `spec/gesamtkonzept.md` §2.5, §2.8, §2.9; `spec/protokoll-spec.md` §10, §13
- **Löst Gate:** GATE-3 (`spec/phase0-spikeplan.md` §4)

## Kontext

GATE-3 verlangt laut `spec/phase0-spikeplan.md` §4 die schriftliche Fixierung
der „Parameter des einheitlichen Netzprofils (Shaping, Intervalle)" auf Basis
von **S4 und S5**.

Warum die Parameter überhaupt fixiert und nicht konfigurierbar sind
(`spec/gesamtkonzept.md` §2.9, wörtlich):

> **Sicherheitsrelevantes Netzverhalten ist nicht konfigurierbar.** Padding-Klassen,
> Sendetakt, Transport-Defaults und Rotationsintervalle sind fest. Jede Option,
> die das Netzverhalten ändert, würde die Nutzerbasis partitionieren und
> Vorsichtige identifizierbar machen.

Und weiter:

> **Es gibt keine Sicherheitsstufen.** Ein Nutzer darf sich nicht durch seine
> Vorsicht verraten.

Der Zielkonflikt, den dieser ADR auflöst, steht in `spec/phase0-spikeplan.md`
§2 (S5): Dauererreichbarkeit kostet Akku; zu hoher Verbrauch führt dazu, dass
Nutzer den Foreground-Service abschalten oder die App entfernen — was das
Zustellmodell zerstört **und** das Anonymitätsset verkleinert. Sparsamere
Parameter schwächen dagegen die Minderungen gegen **G2** (Timing-Korrelation)
und **G3** (Online-Zeiten) aus `spec/threat-model.md`.

**Datengrundlage:**

| Quelle | Liefert | Stand |
|---|---|---|
| S5 (`spikes/S5/`) | Verbrauch je Profilbestandteil (R1−R0, R2−R1, R3−R2, R4−R3), Thermal-Verhalten | **offen — nicht gemessen** |
| S4 | Publikations-Timing vs. Präsenzschutz (Klassifikator-Trefferquote) | <offen> |

## Entscheidung

> Auszufüllen erst nach der Messung. Jedes Feld nennt den belegenden Lauf.
> Ein Feld ohne Beleg bleibt `<offen>` — es wird nicht geschätzt.

### PROFIL-0 — Auslegung des Verbrauchskriteriums
Vor allen Zahlen zu klären (`spikes/S5/MESSPROTOKOLL.md` §2): Bezieht sich
„Zusatzverbrauch < 8 %/24 h" auf das Netzprofil ohne Mesh (R3 − R0) oder auf
alles inklusive Mesh (R4 − R0)?

- **Festlegung:** `<offen>`
- **Begründung:** `<offen>`

### PROFIL-1 — Padding-Größenklassen
- Klassen (Bytes): `<offen>`
- Belegt durch: `<offen — S5-Reihe R3, Differenz R3−R2>`
- Anforderung: eine einzige Klassenmenge für alle Nutzer, keine Aushandlung.

### PROFIL-2 — Sendetakt und Varianz des Alltagsprofils
- Grundtakt: `<offen>` · Varianzmodell: `<offen>`
- Belegt durch: `<offen — S5 R3−R2, S4>`

### PROFIL-3 — Session-Bindung des Shapings
`spec/gesamtkonzept.md` §2.5: „session-gebunden statt dauerhaft".
- Sessionlänge und Abklingverhalten: `<offen>`
- Belegt durch: `<offen>`

### PROFIL-4 — Descriptor-Publikation: Intervall und Jitter
- Intervall: `<offen>` · Jitterbreite: `<offen>`
- Belegt durch: `<offen — S4 (Klassifikator < 60 % Trefferquote), S5 R1−R0>`

### PROFIL-5 — Sync-Fenster
`spec/protokoll-spec.md` §10 legt `INTERVAL = 3600 s` bereits normativ fest
(„Parameter, fest für alle"). Dieser ADR **bestätigt** den Wert oder ändert ihn
begründet — er erfindet ihn nicht neu.
- Bestätigt / geändert auf: `<offen>` · Look-back/-ahead δ: `<offen>`
- Belegt durch: `<offen — S5 R1−R0 (Aufwachhäufigkeit)>`

### PROFIL-6 — Mesh-Beacon-Intervall
`spec/protokoll-spec.md` §13 legt `epoch = floor(t / 30)` fest; das Intervall
geht in die Token-Ableitung ein. Eine Änderung ist eine **Protokolländerung**
und erfordert die Fortschreibung von §13.
- Intervall: `<offen>` (Spec-Stand 30 s; Fallback-Kaskade nennt 60–120 s)
- Belegt durch: `<offen — S5 K-B (R4−R3)>`

### PROFIL-7 — Rotationsintervalle der Identifier
(MAC, Service-IDs, App-Payloads; `spec/gesamtkonzept.md` §2.8)
- Intervall: `<offen>` · Synchronität zwischen den Ebenen: `<offen>`
- Belegt durch: `<offen>`

### PROFIL-8 — Transport-Default
`spec/gesamtkonzept.md` §2.5: Snowflake/meek als Standard.
- Bestätigt / geändert: `<offen>`
- Belegt durch: `<offen — S5 R2−R1>`

### PROFIL-9 — Adaptives Verhalten bei niedrigem Akkustand
- Wird adaptives Verhalten eingeführt? `<offen — ja/nein>`
- Falls ja, verbindlich und ohne Ausnahme:
  - **nur Mesh, niemals das Tor-Profil** (`spec/phase0-spikeplan.md` §2, S5),
  - deterministische, in der Spec fixierte Regel, in allen Clients identisch,
  - genau **ein** Schwellenübergang mit Hysterese, keine kontinuierliche
    Anpassung,
  - kein Nutzerschalter,
  - neues Restrisiko unter **G7** in `spec/threat-model.md` dokumentiert.
- Schwelle: `<offen>` · Verhalten oberhalb/unterhalb: `<offen>`
- Belegt durch: `<offen>`

### PROFIL-10 — Nachweis der Uniformität
Alle oben festgelegten Werte sind **Konstanten im Code**, nicht Einstellungen.
- Prüfung in der CI, die jede Konfigurierbarkeit sicherheitsrelevanter
  Netzparameter verhindert: `<offen — Umsetzung zu definieren>`

## Alternativen

> Zu füllen mit den in der Messung tatsächlich erwogenen Varianten. Bereits
> verworfen und **nicht** erneut aufzurollen (`spec/gesamtkonzept.md` Anhang A):
> Constant-Rate-Mix („Maximum Security"-Modus), wählbare Transportvarianten,
> Direkt-P2P ohne Tor, Sicherheitsstufen im UI.

| Alternative | Erwogen weil | Verworfen weil |
|---|---|---|
| `<offen>` | `<offen>` | `<offen>` |

Die Fallback-Kaskade aus `spec/phase0-spikeplan.md` §2 (S5) ist in dieser
Reihenfolge abzuarbeiten und ihre Anwendung hier zu dokumentieren:
Shaping-Budget → Beacon-Intervall 60–120 s → adaptives Verhalten < 20 % Akku.
Eine Stufe wird nur betreten, wenn die Messung zeigt, dass der Hebel den
Verbrauch überhaupt merklich senkt (Zwischenschritte R2−R1, R3−R2, R4−R3);
sonst wird Schutz ohne Gegenwert geopfert.

## Auswirkung auf das Threat Model

**Pflichtfeld.**

- **G2 (Ende-zu-Ende-Timing-Korrelation)** — heute mit ◐ gemindert durch
  Padding auf Größenklassen und Alltags-Shaping. Ein reduziertes Shaping-Budget
  schwächt diese Minderung. Ausmaß: `<offen>`
- **G3 (Online-Zeiten aus Verbindungsaufkommen, Intersection-Angriffe)** —
  gemindert durch session-gebundenes Shaping und gestreute Publikation.
  Auswirkung der gewählten Intervalle: `<offen>`
- **G7 (physisches Tracking über Mesh-Beacons)** — ein längeres Beacon-Intervall
  verlängert die Gültigkeit eines Tokens; die Challenge-Response-Frische bleibt
  wirksam. Auswirkung: `<offen>`. Bei adaptivem Verhalten (PROFIL-9) entsteht
  ein **neues Restrisiko**: Die Senderate verrät einem physisch anwesenden
  Beobachter einen Gerätezustand und teilt die Beacon-Population in zwei
  Klassen. Bewertung: `<offen>`
- **Anonymitätsset (`spec/gesamtkonzept.md` §2.9)** — solange alle Parameter
  global und fest sind, bleibt die Nutzerbasis unpartitioniert. Jede
  zustandsabhängige Anpassung verkleinert das Anonymitätsset; jede
  nutzerseitige Einstellbarkeit ist unzulässig. Prüfergebnis: `<offen>`
- **Gegenläufiger Effekt, ausdrücklich zu würdigen:** Ein zu hoher Verbrauch
  führt zu Deinstallation und abgeschaltetem Foreground-Service. Das verkleinert
  das Anonymitätsset ebenfalls (`spec/phase0-spikeplan.md` §2, S5:
  „beides zerstört das Zustellmodell **und** verkleinert das Anonymitätsset").
  Der ADR muss beide Richtungen abwägen, nicht nur die Härtungsseite.

## Auswirkung auf den Prioritätsstack

- **Priorität 1 (Anonymität):** berührt. Zulässig nur, solange die Parameter für
  alle Nutzer identisch und nicht konfigurierbar bleiben (§2.9, ADR-09). Eine
  Variante, die einzelne Nutzer oder Gerätezustände unterscheidbar macht, ist
  **nicht zulässig** und wäre nach `CLAUDE.md` zu melden statt umzusetzen.
- **Priorität 2 (Serverlosigkeit):** nicht berührt. Kein Parameter dieses
  Profils setzt Infrastruktur voraus; Snowflake/meek nutzen das öffentliche
  Tor-Netz, keinen Betreiber-Backend-Dienst.
- **Priorität 3:** Latenz und Zustellgeschwindigkeit sind der bewusst opferbare
  Teil.

## Konsequenzen

- Leichter: Alle Netzparameter stehen an einer Stelle und sind prüfbar;
  Abweichungen im Code werden zu einem CI-Verstoß statt zu einer Option.
- Schwerer: Jede spätere Änderung eines Wertes ist eine Protokolländerung mit
  Kompatibilitätsfolgen (besonders PROFIL-6, das in die Token-Ableitung
  eingeht) und braucht einen neuen ADR.
- Folgearbeiten:
  - Fortschreibung von `spec/protokoll-spec.md` §13, falls PROFIL-6 vom
    Spec-Stand 30 s abweicht,
  - Ergänzung von `spec/threat-model.md` um das Restrisiko aus PROFIL-9,
    falls adaptives Verhalten eingeführt wird,
  - CI-Prüfung nach PROFIL-10,
  - Wiederholungsmessung nach jeder Parameteränderung — das Mess-Kit unter
    `spikes/S5/tools/` ist dafür wiederverwendbar.
