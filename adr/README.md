# Architecture Decision Records

ADR-01 bis ADR-14 sind in `spec/engineering-setup.md` §1 tabellarisch
fixiert und **verbindlich**. Dieses Verzeichnis nimmt alle weiteren ADRs auf
— insbesondere GATE-1 bis GATE-6 aus `spec/phase0-spikeplan.md` §4, die am
Ende von Phase 0 schriftlich zu fixieren sind.

Regel aus `CLAUDE.md`: **Abweichung von der Spec nur mit neuem ADR** — mit
Begründung, Alternativen und Auswirkung auf das Threat Model. Ohne ADR ist
eine Abweichung ein Blocker.

## Dateiname

`adr/ADR-<NN>-<kurzer-slug>.md`, fortlaufend, keine Nummer wird
wiederverwendet.

## Vorlage

```markdown
# ADR-<NN>: <Titel>

- **Status:** vorgeschlagen | akzeptiert | ersetzt durch ADR-<NN>
- **Datum:** JJJJ-MM-TT
- **Betrifft:** <Crates / Spec-Abschnitte>
- **Löst Gate:** <GATE-N oder —>

## Kontext

Welches Problem steht an? Welche Spec-Abschnitte sind einschlägig
(wörtlich zitieren)? Welcher Spike liefert die Datengrundlage?

## Entscheidung

Was wird festgelegt. Eindeutig, ohne Konjunktiv.

## Alternativen

Was wurde erwogen und warum verworfen. Ansätze aus Anhang A des
Gesamtkonzepts sind bereits verworfen und werden hier nicht erneut
aufgerollt.

## Auswirkung auf das Threat Model

**Pflichtfeld.** Welche Angreiferklasse aus `spec/threat-model.md` gewinnt
oder verliert dadurch? Entsteht ein neues Restrisiko? Verändert sich das
Anonymitätsset (`spec/gesamtkonzept.md` §2.9)?

## Auswirkung auf den Prioritätsstack

Berührt die Entscheidung Priorität 1 (Anonymität) oder 2 (Serverlosigkeit)?
Wenn ja: warum ist sie trotzdem vertretbar? Wenn eine der beiden verletzt
würde, ist die Entscheidung nicht zulässig, sondern zu melden.

## Konsequenzen

Was wird dadurch leichter, was schwerer. Welche Folgearbeiten entstehen.
```
