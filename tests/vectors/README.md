# Krypto-Testvektoren

Normativ: `spec/engineering-setup.md` §3.2 — „Bekannte Testvektoren +
Property-Tests; Differential-Test gegen Referenzimplementierung". Gate G-2
(„Tests grün inkl. Krypto-Vektoren").

## Inhalt (geplant)

| Datei | Gegenstand | Quelle |
|---|---|---|
| — | PQXDH: X25519 + ML-KEM-768 (CR-1) | Signal-PQXDH-Spezifikation, NIST-KAT für ML-KEM |
| — | Double Ratchet (CR-2) | Referenzvektoren der Bibliothek |
| — | HKDF-SHA-256 | RFC 5869 Anhang A |
| — | XChaCha20-Poly1305 | RFC 8439 + XChaCha-Draft |
| — | BLAKE3-256 | offizielle Testvektoren |
| — | Deterministisches CBOR (S7) | 500 Testvektoren, identische Bytes über Rust/Dart |

Derzeit leer: `vault-crypto` enthält bewusst keine Implementierung, gegen die
sich Vektoren prüfen ließen (ADR-05 — keine Eigenentwicklung, keine
Platzhalter-Krypto). Die Vektoren kommen zusammen mit Sprint 0 #4.

Für das CBOR-Profil existieren bereits Positiv- und Negativfälle als
Unit-Tests in `core/vault-wire/src/cbor.rs`; die plattformübergreifenden
S7-Vektoren gehören später hierher.
