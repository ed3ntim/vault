# Spike S3 — Revocation-Latenz (Descriptor-Republish)

**Spec:** `spec/phase0-spikeplan.md` §1 (S3), §3 (Kriterium/Fallback), §4, §6 ·
`spec/protokoll-spec.md` §11 · `spec/gesamtkonzept.md` §2.2 ·
ADR-15 (erzwungene Intro-Point-Rotation) · ADR-16 (Tor-Stack vorlaeufig)

**Kriterium:** Revocation → Verbindungsverlust des Revozierten in < 5 min (p95);
Intro-Point-Rotation greift.

**Ergebnis in einem Satz:** siehe `BERICHT.md`. Kurz: Der Prototyp und alle
offline messbaren Teilgroessen liegen vor und sind gemessen; die eigentliche
Zeitmessung im laufenden Tor-Netz war in dieser Umgebung nicht durchfuehrbar
(Konsens-Download schliesst nicht ab, wie in S1).

## Artefakte

| Pfad | Inhalt | laeuft ohne Netz |
|---|---|---|
| `rot-proto/` | Wegwerf-Prototyp der erzwungenen Rotation nach §11 (Zustandsmaschine + echte Descriptor-Kryptografie) | ja |
| `rot-proto/src/bin/rot_offline.rs` | Messprogramm R1–R8 | ja |
| `rot-proto/tests/rotation.rs` | 13 Integrationstests der §11-Invarianten | ja |
| `rotations-api/` | Compilerprobe: welche Hebel bietet arti 0.44.0 fuer die Rotation | ja |
| `s3-live/` | Ende-zu-Ende-Messrig gegen das echte Tor-Netz (Varianten A/B) | **nein** |
| `pruefe-rotations-api.sh` | reproduziert die API-Messung | ja |
| `pruefe-arti-konstanten.sh` | liest die zeitbestimmenden Konstanten aus dem Quelltext | ja |
| `live-versuch.sh` | fuehrt das Messrig aus und protokolliert | nein |
| `ergebnisse/` | Rohausgaben aller Laeufe | — |

## Reproduktion

```sh
cd spikes/S3/rot-proto && cargo run --release --bin rot-offline   # R1-R8, offline
cd spikes/S3/rot-proto && cargo test --release                    # 16 Tests
bash spikes/S3/pruefe-rotations-api.sh                            # API-Hebel
bash spikes/S3/pruefe-arti-konstanten.sh                          # Konstanten
bash spikes/S3/live-versuch.sh ab 1800 15 600                     # braucht Tor-Zugang
```

`spikes/S3/s3-live/run/` (Arti-Zustands- und Cacheverzeichnisse der Laeufe)
ist Wegwerfzustand und gehoert nicht ins Repository.
