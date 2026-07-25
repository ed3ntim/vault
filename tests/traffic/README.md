# Metadaten- und Fingerprint-Analyse

Normativ: `spec/engineering-setup.md` §3.2 — „Automatisierte
Fingerprint-Analyse: Klassifikator darf App-Traffic nicht > 60 % erkennen".
Verwandt: `spec/gesamtkonzept.md` §2.9 (Ununterscheidbarkeit),
`spec/phase0-spikeplan.md` S4 (Publikations-Timing, Klassifikator < 60 %).

## Was hier entsteht

- Aufzeichnung und Klassifikation von Verkehrsmustern der App gegen
  Fremdverkehr (Snowflake/meek-Kohorte)
- Prüfung der Publikations-Timing-Korrelation aus S4
- Regressionsschwelle: Trefferquote des Klassifikators ≤ 60 %

Derzeit leer: es gibt noch keinen Transport, der Verkehr erzeugt. Die Suite
gehört zu Phase 3 (Anti-SIGINT-Härtung), die Schwelle gilt ab dann als Gate.
