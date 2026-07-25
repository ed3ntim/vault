# Fuzz-Targets (Gate G-8)

Normativ: `spec/engineering-setup.md` §3.2 — „Dauerhafte Fuzz-Targets:
`Invitation`, `Envelope`, `GroupFrame`, `Attestation`" — und §4, Gate G-8
(„Fuzzing-Smoke; kurze Läufe, lange Läufe nightly").

## Ausführen

```sh
# Smoke wie in CI (30 s je Target)
ops/ci/g8-fuzz-smoke.sh

# einzelnes Target, länger
cargo +nightly fuzz run --fuzz-dir tests/fuzz invitation -- -max_total_time=600
```

`cargo-fuzz` benötigt nightly. Der Kern selbst bleibt auf dem in
`core/rust-toolchain.toml` gepinnten Stable — nightly ist Werkzeug, kein
Build-Input für Releases (G-9).

## Aktuelle Deckung — ehrlich benannt

Alle vier Targets existieren unter den in §3.2 geforderten Namen, decken aber
**heute nur die gemeinsame Parserbasis** ab:

- `vault_wire::cbor::validate_canonical` — deterministisches CBOR nach
  RFC 8949 §4.2
- `vault_wire::lenprefix::FieldReader` — längenpräfigierte Felder

Die typspezifischen Decoder für `Invitation` (`spec/protokoll-spec.md` §4),
`Envelope` (§8), `GroupFrame` (§12) und `Attestation` (`spec/gruppen-spec.md`
§5) existieren noch nicht. Sie entstehen in Sprint 0 #3 und werden **in
dieselben Targets** eingehängt; erst dann ist die Anforderung aus §3.2
vollständig erfüllt.
