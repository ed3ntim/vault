# Spike S1 — Tor-Stack: Arti vs. C-tor

Wegwerf-Code zur Entscheidungsfindung für GATE-1
(`spec/phase0-spikeplan.md` §2 S1, §4). **Kein Produktionscode**, nichts hiervon
wandert nach `core/` oder `app/`.

Ergebnisse: [`BERICHT.md`](BERICHT.md) · ADR-Entwurf:
[`adr-entwurf-GATE-1.md`](adr-entwurf-GATE-1.md)

## Inhalt

| Verzeichnis | Zweck | Netz nötig |
|---|---|---|
| `desc-auth/` | Erfolgskriterium 3: nicht-autorisierter Descriptor-Abruf scheitert. Baut einen v3-Descriptor mit Restricted Discovery und versucht ihn mit autorisierten/nicht-autorisierten Schlüsseln zu entschlüsseln. | nein |
| `api-nonexp/` | Belegt per Compilerlauf, welche Client-Auth-APIs in arti-client 0.44.0 ohne `experimental-api` verfügbar sind. | nein |
| `netcheck/` | Ist das Tor-Netz aus der Umgebung erreichbar? TCP-Connect gegen Directory-Authorities bzw. übergebene Adressen. | ja |
| `arti-probe/` | Ende-zu-Ende: Onion-Service mit `static_keys` starten, autorisierter Client verbindet, nicht-autorisierter scheitert; Zeitmessung. | ja |
| `ergebnisse/` | Rohausgaben der tatsächlich gelaufenen Messungen. | — |

## Reproduktion

```sh
# Kriterium 3, offline, ~2 s Laufzeit
cd desc-auth && cargo run --release

# API-Oberflaeche (erwartet: [1] uebersetzt, [2] uebersetzt nicht)
bash ../pruefe-api-oberflaeche.sh

# Erreichbarkeit des Tor-Netzes
cd netcheck && rustc -O -o netcheck.exe src/main.rs && ./netcheck.exe

# Ende-zu-Ende gegen das echte Tor-Netz: 12 Verbindungslaeufe, 240 s Timeout
cd arti-probe && cargo run --release --bin bootstrap-timing -- 12 240
```

## Hinweise

- `arti-probe` legt seinen Arti-Zustand unter `arti-probe/run/` an (gitignored
  über `spikes/**/target/` nicht abgedeckt — vor dem Commit löschen).
- `arti-probe` braucht `experimental-api`; genau das ist ein Messergebnis.
- Auf Android ist `native-tls` nicht gangbar (verlangt cross-kompiliertes
  OpenSSL). Mit `rustls` muss vor dem ersten Aufruf ein
  `rustls::crypto::CryptoProvider` explizit installiert werden, sonst paniert
  der Prozess.
- Onion-Adressen werden nicht geloggt (`CLAUDE.md`: keine Onion-Adressen in
  Logs); das Messprogramm gibt nur Zeiten und Ergebnisse aus.
