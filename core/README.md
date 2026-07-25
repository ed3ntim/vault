# Rust-Kern

Workspace nach `spec/engineering-setup.md` §2. Normativ sind die Specs in
`spec/`; bei Widerspruch zwischen Code und Spec gewinnt die Spec.

## Crates

| Crate | Inhalt | Abhängigkeiten (intern) |
|---|---|---|
| `vault-crypto` | PQXDH, Double Ratchet, AEAD, KDF | — (keine I/O, kein Netz) |
| `vault-wire` | CBOR-Typen, deterministische Kodierung | — |
| `vault-transport` | Transport-Trait, `tor/`, `mesh/` | — (kennt keine Klartext-Payloads) |
| `vault-identity` | IK, Kompartimente, Credentials, Geräteliste | crypto, wire |
| `vault-delivery` | Queue, Routing, ACK-FSM, Sync-Fenster | wire, transport, identity |
| `vault-groups` | MLS-Wrapper, Sequencer, Attestation, Pairwise | crypto, wire, identity |
| `vault-storage` | SQLCipher, Migrationen, Keystore-Adapter | wire, identity |
| `vault-core` | Orchestrierung, öffentliche API | alle obigen |
| `vault-ffi` | `flutter_rust_bridge`-Grenze | core |

Die beiden Sonderregeln in Spalte 3 sind die **Schichtregel** aus §2 und
werden von Gate G-5 erzwungen, nicht nur dokumentiert.

## Stand

Alles außer `vault-wire` ist Gerüst: Modulgrenzen, Doku mit Spec-Referenz und
typisierte Fehler. Bewusst **keine** Platzhalter-Implementierungen — für
Krypto ist das nach `CLAUDE.md` verboten, für den Rest wäre es irreführend.

In `vault-wire` sind zwei Bausteine echt und getestet:

- `cbor::validate_canonical` — deterministisches CBOR nach RFC 8949 §4.2
  (`spec/protokoll-spec.md` §1)
- `lenprefix` — längenpräfigierte Felder für Signatur-Eingaben (§1, `‖`)

Beide ohne externe Abhängigkeit, weil Spike S7 und GATE-6 („Wire-Format
final") offen sind. Der Workspace hat deshalb derzeit **null**
Registry-Abhängigkeiten.

## Gates lokal fahren

```sh
ops/ci/all.sh              # G-2 … G-8
ops/ci/g5-layers.sh        # einzeln
FUZZ_SECONDS=300 ops/ci/g8-fuzz-smoke.sh
```

Voraussetzungen: `cargo install --locked cargo-deny cargo-vet cargo-fuzz`
und `rustup toolchain install nightly` (nur für G-8).

## Toolchain

`rust-toolchain.toml` pinnt Stable exakt — Voraussetzung für G-9
(reproduzierbarer Build). Nightly wird ausschließlich von `cargo fuzz`
benutzt und ist kein Build-Input für Releases.
