# Vault Messenger — Technische Spezifikation (Protokoll-Flows)

**Implementierungsgrundlage. Ergänzt das Gesamtkonzept um konkrete Formate, Sequenzen und Zustandsautomaten.**

Diese Spezifikation ist normativ für: Invitation, Kontakt-Handshake, Verifikation, Kompartiment-/Credential-Verwaltung, Session & Messaging, Zustellung, Multi-Device-Routing, Sync-Fenster, Revocation, Mesh-Discovery. Gruppen sind hier nur als Schnittstelle skizziert (eigene Spec).

---

## 1. Notation & Primitive

| Symbol | Bedeutung |
|---|---|
| `Ed25519` | Signatur / Onion-Service-Identität |
| `X25519` | ECDH-Schlüsselaustausch |
| `ML-KEM-768` | Post-Quantum-KEM (Kyber) |
| `HKDF` | HKDF-SHA-256 (Extract-and-Expand) |
| `H(x)` | BLAKE3-256 |
| `AEAD(k, n, ad, pt)` | XChaCha20-Poly1305 |
| `Sig(sk, m)` / `Vrf(pk, m, σ)` | Ed25519 |
| `‖` | Byte-Konkatenation mit Längenpräfix |
| `KDF_RK`, `KDF_CK` | Double-Ratchet-Root/Chain-KDF |

Alle Multi-Byte-Felder little-endian, alle Zeitstempel `u64` Unix-Sekunden. Wire-Kodierung: **CBOR** (deterministisch, RFC 8949 §4.2). Kein Feld ohne explizite Länge.

---

## 2. Schlüsselhierarchie

```
IK  (Ed25519 Identitäts-Root)         ── stabil, nie direkt im Netz exponiert
 │   IK_x = X25519(IK)                    (aus demselben Seed, für ECDH)
 │
 ├─ signiert ─▶ OSK_c (Ed25519)         Onion-Service-Key je Kompartiment c
 │                 └─ onion_c = tor_v3_addr(OSK_c_pub)
 │
 ├─ signiert ─▶ DEVK_d (Ed25519)        Geräteschlüssel je eigenem Gerät d
 │
 └─ PQXDH-Prekeys:
      SPK   (X25519, signiert von IK, rotierend)
      PQSPK (ML-KEM ek, signiert von IK, rotierend)
      OPK[] (X25519, einmalig)          optional
      PQOPK[] (ML-KEM ek, einmalig)     optional

Pro Kontakt X in Kompartiment c:
   CA_{c,X}  (X25519)  Tor-Client-Auth-Schlüsselpaar
      CA_pub  → in authorized_clients von OSK_c (bei mir)
      CA_priv → an X übergeben (X entschlüsselt damit meinen Descriptor)

Pro Sitzung mit X:
   Double-Ratchet-Zustand DR_X (RK, CKs, CKr, DHs, DHr, Nr, Ns, PN, skipped[])
   sync_key_X = HKDF(DR_X.RK_initial, "vault-sync-window")
   mesh_key_X = HKDF(shared_secret_X, "vault-mesh-beacon")
```

**Grundsatz:** `IK` signiert alles Abgeleitete → ein Kontakt kann jede Kompartiment-Adresse, jeden Geräteschlüssel und jedes Prekey-Bundle auf dieselbe Identität zurückführen. Kompromittiert ein Angreifer eine Kompartiment- oder Geräte-Ableitung, bleibt `IK` unberührt (out of scope, aber sauber isoliert).

---

## 3. Identitäts- & Kompartiment-Strukturen (lokal)

```
Identity {
  ik_ed_priv, ik_ed_pub
  ik_x_priv,  ik_x_pub
  created_at
}

Compartment {
  id: u8                      // lokaler Index 0..N
  label: string               // UI: "privat" / "beruflich" / "hochsensibel"
  osk_ed_priv, osk_ed_pub
  onion_addr                  // = tor_v3_addr(osk_ed_pub)
  osk_cross_sig               // = Sig(ik_ed_priv, osk_ed_pub ‖ id)
  authorized_clients: Map<contact_id, CA_pub>
  intro_point_epoch: u32      // erhöht bei Revocation → Descriptor-Neuveröffentlichung
}

Contact {
  contact_id: H(ik_ed_pub_of_contact)
  ik_ed_pub, ik_x_pub         // Identität der Gegenseite
  compartment_id
  their_onions: []            // signierte Geräteliste der Gegenseite
  ca_priv_to_reach_them       // CA_priv, das SIE mir gegeben haben
  dr: DoubleRatchetState
  sync_key, mesh_key
  assurance: {UNVERIFIED, CONFIRMED, VERIFIED}   // ⚪ / 🔵 / 🟢
  disappearing_ttl            // Default gesetzt
  state: ContactFSM
}
```

---

## 4. Invitation-Format

Erzeugt von Alice, out-of-band an Bob (QR / NFC / Link). Einmalig, kurzlebig, replay-fest.

```
Invitation {
  v: u8 = 1
  inviter_ik_ed_pub                         // Alices Identität
  inviter_ik_x_pub
  compartment: {
    onion_addr                              // Alices Kompartiment-Adresse
    osk_ed_pub
    cross_sig                               // Sig(IK, osk_ed_pub ‖ id)
    ca_priv                                 // Client-Auth-PRIV für Bob
  }
  prekey_bundle: {
    spk_x_pub,  spk_sig                      // Sig(IK, spk_x_pub)
    pqspk_ek,   pqspk_sig
    opk_x_pub?  ,                            // optional einmalig
    pqopk_ek?
  }
  invite_nonce: 16B                          // einmalig, serverlos via lokalem Store
  expires_at                                 // z.B. now + 72h
  sig                                        // Sig(IK, H(alle vorstehenden Felder))
}
```

- **QR-Pfad:** Der QR enthält zusätzlich `H(IK_ed_pub)` visuell prominent → Bob-Gerät prüft Übereinstimmung; da persönlich, ist MITM ausgeschlossen → direkt `VERIFIED (🟢)`.
- **Link-Pfad:** Assurance zunächst `CONFIRMED (🔵)` erst nach erfolgreicher SMP (§7), sonst `UNVERIFIED (⚪)`.
- **Replay:** `invite_nonce` wird bei Erstellung in Alices `used_nonces`-Store vermerkt; Bob-Reply trägt die Nonce, Alice akzeptiert sie genau einmal.
- **Größe:** vollständige Invitation ~400–600 B → als QR (Version ≤ 20) darstellbar; bei einmaligen PQOPKs ggf. Link/NFC.

---

## 5. Kontakt-Handshake (asynchron-fähig)

Ziel: bidirektionale Erreichbarkeit + etablierte Double-Ratchet-Sitzung, ausgehend von einer einseitigen Invitation.

```
Alice                                   Bob
  │  (out-of-band: Invitation I_A) ─────▶│
  │                                      │  verify I_A.sig, expires_at
  │                                      │  connect onion_A via ca_priv (Tor client-auth)
  │                                      │
  │                                      │  PQXDH als Initiator:
  │                                      │   EK_x  ← X25519 ephemeral
  │                                      │   (K_pq, ct_pq) ← ML-KEM.Encaps(pqspk_ek)
  │                                      │   DH1 = X25519(EK_x,  spk_x_pub)
  │                                      │   DH2 = X25519(ik_x_B, spk_x_pub)
  │                                      │   DH3 = X25519(EK_x,  ik_x_A_pub)
  │                                      │   [DH4 = X25519(EK_x, opk) falls vorhanden]
  │                                      │   SK = HKDF(DH1‖DH2‖DH3‖[DH4]‖K_pq)
  │                                      │   init DR_B mit SK
  │                                      │
  │   ◀───── FirstMessage ───────────────│  AEAD unter DR, enthält ContactCard C_B:
  │        {EK_x_pub, ct_pq, C_B, ad}    │    { ik_ed_B, ik_x_B,
  │                                      │      compartment_B.onion, osk_ed_B, cross_sig_B,
  │                                      │      ca_priv_for_alice,     // damit Alice Bob erreicht
  │                                      │      device_list_B (signiert),
  │                                      │      invite_nonce }         // Replay-Bindung
  │                                      │
  │ verify cross_sig_B, device_list_B    │
  │ consume invite_nonce (genau einmal)  │
  │ init DR_A (spiegelbildlich), store Bob│
  │ add CA_pub_for_bob → authorized(c)   │  (bereits via ca_priv geschehen)
  │ add CA_pub_of_bob-supplied → reach B │
  │                                      │
  │  ─────── AckEstablished ────────────▶│  DR-verschlüsselt
  │        {device_list_A (signiert)}    │  Bob speichert Alices Geräteliste
  │                                      │
  │        beide: state = ESTABLISHED    │
  │        optional SMP (§7) ──────────  │  → VERIFIED/CONFIRMED
```

**Wichtig:** Bevor SMP/QR-Verifikation abgeschlossen ist, ist die Sitzung technisch nutzbar, aber die UI zeigt die Assurance-Stufe deutlich an. Ein MITM beim Link-Austausch säße hier — genau deshalb ist SMP für den Link-Pfad verpflichtend, bevor `CONFIRMED` gesetzt wird.

---

## 6. Kompartiment- & Credential-Verwaltung

**Kontakt zu Kompartiment `c` hinzufügen:**
```
CA ← X25519.keygen()
compartment[c].authorized_clients[contact_id] = CA.pub
tor: set_client_auth(onion_c, CA.pub)
republish_descriptor(onion_c)          // jetzt für neuen Client entschlüsselbar
invitation.ca_priv = CA.priv           // an Kontakt übergeben
```

**Descriptor-Veröffentlichung (Präsenzschutz):**
- Publikationszeitpunkte werden **randomisiert gestreut** (kein fester Takt), abgeleitet aus `HKDF(osk, "pub-jitter" ‖ time_slot)`.
- Client-Auth stellt sicher: nur autorisierte Kontakte rufen den Descriptor ab; das Netz sieht nur an unbekannte Schlüssel verschlüsselte Blobs.

---

## 7. Verifikation

**QR-bei-Treffen (Goldstandard):** Fingerprint `H(IK_ed_pub)` wird visuell verglichen bzw. im QR mitgeführt. Kein MITM möglich → `VERIFIED (🟢)`.

**Remote — SMP (Socialist Millionaire Protocol):** über den etablierten DR-Kanal.
```
Eingabe beider Seiten: gemeinsames Geheimnis s (nur beiden bekannt)
Ablauf (Standard-SMP über die Ratchet-Session):
  1. a2,a3,b2,b3 ← Zufall
  2. Austausch g2=g^a2, g3=g^a3 (+ ZK-Beweise)
  3. Pa,Qa / Pb,Qb aus s ableiten, austauschen (+ ZK-Beweise)
  4. Rab prüfen → equal? 
Ergebnis: nur "s gleich?" wird offenbart, s selbst nie.
equal  → VERIFIED-über-Vorwissen → assurance = CONFIRMED (🔵),
         bei zusätzlichem QR-Kontext VERIFIED (🟢)
¬equal → Warnung "möglicher MITM", Kontakt bleibt UNVERIFIED (⚪)
```
SMP ist **stimmklonungsfest**, weil kein Sprachkanal beteiligt ist. Der frühere SAS-Wortvergleich bleibt als Zusatz verfügbar, gilt aber nicht als hinreichend (Stimmklonung).

---

## 8. Session & Messaging

**Double Ratchet** wie Signal-Spezifikation, initialisiert aus PQXDH-`SK`. Pro Nachricht DH-Ratchet bei Richtungswechsel, symmetrischer Ratchet je Nachricht.

**Envelope (Wire):**
```
Envelope {
  transport_tag: 8B         // EPHEMER pro Transport, NICHT stabil über Transporte (§13)
  dr_header: { dh_pub, pn, n }
  ciphertext                // AEAD(mk, nonce, ad=H(dr_header), pt=Payload)
}
```
`transport_tag` wird pro Transport (Tor-Stream vs. Mesh-Frame) frisch gezogen; er dient nur der Frame-Zuordnung, nie der geräteübergreifenden Wiedererkennung → Cross-Transport-Korrelation ausgeschlossen.

**Payload-Typen:**
```
enum Payload {
  Text { body, ttl }
  Attachment { key, size, chunk_count, manifest_hash }   // Chunks separat, XChaCha20
  Ack { msg_id }                                          // setzt Status "delivered"
  Receipt { msg_id, kind: DELIVERED|READ }                // READ opt-in
  ContactCard { ... }                                     // §5
  DeviceListUpdate { list, sig }
  SyncRecord { ... }                                      // Multi-Device (§9)
  GroupCtrl { ... }                                       // eigene Spec
  RevocationNotice { ... }                                // §11
}
```
`msg_id = H(dr_header ‖ ciphertext)` — deterministisch, kollisionsresistent, **nur innerhalb der entschlüsselten Session sichtbar** (nicht auf der Wire).

---

## 9. Zustellung & Multi-Device-Routing

### 9.1 Geräteliste
Jedes eigene Gerät hat `DEVK_d`, von `IK` signiert. Die **DeviceList** (Menge der Kompartiment-Onions aller eigenen Geräte) wird von `IK` signiert und an Kontakte via `DeviceListUpdate` propagiert.
```
DeviceList { entries: [{ device_id, onion_addr_per_compartment[] }], epoch, sig }
```

### 9.2 Sende-Routing (an Kontakt X)
```
targets = sort(X.their_onions, by=priority_deterministic)   // stabile Reihenfolge
for onion in targets:
    if reachable(onion):
        deliver(onion, envelope); await Ack(timeout)
        if Ack: mark DELIVERED; break
if kein Ack:
    enqueue_persistent(X, envelope)      // Ausgangswarteschlange, Status WAITING
    schedule_retry()                     // bei Sync-Fenster (§10) / Erreichbarkeit
```
Die **deterministische Zielreihenfolge** sorgt dafür, dass normalerweise **dasselbe Empfängergerät** die Nachricht erhält und damit die Ratchet der Gegenseite vorantreibt → Nebenläufigkeits-Konflikte selten.

### 9.3 Empfang & Geräte-Rollen (Primärgerät-Modell, GATE-2 / ADR-17)

Der Double-Ratchet-Zustand einer Kontakt-Session existiert **nur auf dem Primärgerät**. Zweitgeräte halten keinen eigenen Ratchet-Zustand für Kontakte.

- **Empfang:** Nur das Primärgerät entschlüsselt eingehende Kontakt-Envelopes und treibt die Ratchet voran. Es setzt das E2E-ACK; `delivered` wird ausschließlich vom Primärgerät gesetzt.
- **Zweitgeräte sind Read-Through-Replikate:** Sie erhalten entschlüsselte Verläufe per `SyncRecord` über das Intra-Identity-Mesh, reichen aber eingehende Kontakt-Envelopes nur als **opake Bytes** ans Primärgerät weiter, ohne sie zu entschlüsseln.
- **Senden vom Zweitgerät:** als Send-Proxy über das Primärgerät. Ist das Primärgerät nicht erreichbar, zeigt das Zweitgerät ehrlich „nicht sendefähig" statt eine Ratchet-Operation zu simulieren.
- **Rollenwechsel** (Primärgerät verloren/gewechselt) ist ein eigener, noch ungetesteter Ablauf → Restrisiko **R-11**, Spike vor Phase 2.

**Begründung:** Der Double Ratchet ist ein Zwei-Parteien-Protokoll; sein Sendezustand ist nicht über mehrere Geräte replizierbar. Die frühere Fassung (paarweiser Multi-Device-Ratchet) verlor strukturell Nachrichten (Spike S2: 4,15 % untere Schranke) und ist verworfen.

### 9.4 Zustellstatus-FSM
```
QUEUED ──attempt──▶ ATTEMPTING ──Ack──▶ DELIVERED ──Receipt──▶ READ
   ▲                    │
   └── kein reachable ──┴─▶ WAITING ──(Sync-Fenster/Erreichbarkeit)──▶ ATTEMPTING
```
UI zeigt `WAITING` als „wartet auf Erreichbarkeit" — nie „zugestellt".

---

## 10. Sync-Fenster-Ableitung

Erhöht die Online-Überlappung zweier Kontakte ohne Infrastruktur, unauffällig und pro Paar verschieden.
```
INTERVAL = 3600 s                        // stündliches Grundraster (Parameter, fest für alle)
slot(t)  = floor(t / INTERVAL)
off      = HMAC(sync_key_X, slot(t)) mod INTERVAL     // gemeinsamer Offset im Intervall
jitter   = HMAC(sync_key_X, slot(t) ‖ 0x01) mod 60    // ±-Streuung gegen Sekundenkorrelation
window_center(t) = slot(t)*INTERVAL + off + jitter
```
Beide Clients berechnen identische `window_center` (gemeinsamer `sync_key_X`), erscheinen dort kurz online und leeren wechselseitige Warteschlangen. Da `sync_key_X` pro Paar einzig ist, ergibt sich für einen Außenstehenden **kein globales Muster**. `INTERVAL` ist Teil des einheitlichen, nicht konfigurierbaren Netzprofils (§2.9 Gesamtkonzept).

Lockere Uhr-Synchronität: Empfänger akzeptiert Zustellversuche im Fenster `[center-δ, center+δ]` (Look-back/-ahead), kein NTP nötig.

---

## 11. Revocation (granular)

Feindlich gewordenen Kontakt X vollständig trennen:
```
c = X.compartment_id
1. compartment[c].authorized_clients.remove(X.contact_id)
2. compartment[c].intro_point_epoch += 1
3. tor: rotate_intro_points(onion_c); republish_descriptor(onion_c)
        → X kann neuen Descriptor nicht mehr entschlüsseln, alte Intro-Points tot
4. mesh_visibility.remove(X)             // §13: kein Beacon mehr für X berechenbar
5. drop DR_X, purge session keys (zeroize)
6. replicate RevocationNotice an eigene Geräte (SyncRecord)
```
Ergebnis in einem Schritt: **kein Reach, keine Präsenz-Sicht, kein Mesh-Tracking** mehr für X. Andere Kontakte im selben Kompartiment unberührt. Keine Neu-Verifikation nötig.

> Restlinkbarkeit: Teilen mehrere Kontakte dasselbe Kompartiment, wissen zwei kompromittierte darunter, dass sie dieselbe Person kennen. Hochsensible Kontakte daher in eigenes, minimal besetztes Kompartiment (UI-Führung).

---

## 12. Gruppen (Schnittstelle)

Nur Übergabepunkte; Details in eigener Spec.
- **MLS-Modus:** `GroupCtrl` transportiert opake MLS-Handshake-Blobs; ein rotierender **Peer-Sequencer** ordnet sie (liest nichts). Mitglieder signieren und gossippen **Transcript-Hashes** je Epoche → Equivocation erkennbar.
- **Pairwise-Fanout-Modus:** Gruppe = N paarweise 1:1-Sessions; jede Nachricht trägt `transcript_hash`; Divergenz zwischen Empfängern wird gemeldet (Content-Equivocation-Schutz).

---

## 13. Mesh-Discovery (PSI-Beacon)

Kontakt-Erkennung in physischer Nähe ohne Identifier-Leak.
```
Beacon (rotierend, alle ~30 s):
  epoch  = floor(t / 30)
  chal   = 16B Zufall                     // Frische gegen Replay
  Für jeden Kontakt X mit aktiver Mesh-Sichtbarkeit:
     tok_X = HMAC(mesh_key_X, epoch)[0..10]     // kurzer Erkennungstoken
  Broadcast: { epoch, chal, bloom(tok_X über alle X) }   // Bloom-Filter, O(1)-Prüfung
```
- Empfänger prüft mit **eigenem** `mesh_key_X` gegen den Bloom-Filter → erkennt nur echte Kontakte; ein Sniffer sieht rotierendes Rauschen.
- **Replay-Schutz:** anschließender Handshake bindet `chal` (Challenge-Response) → aufgezeichnete Beacons sind wertlos, keine Ortsplatzierung.
- **Akku-Schutz:** Bloom-Filter macht die Prüfung eingehender Beacons konstant statt O(N); Rate-Limit pro Quelle.
- **Revocation:** `mesh_key_X` bei Revocation gelöscht → für X kein Token mehr berechenbar → kein Tracking.
- **Cross-Transport-Isolation:** Mesh-Frames tragen eigene ephemere `transport_tag`; dieselbe Nachricht ist über Tor und Mesh nicht verkettbar.

---

## 14. Zustandsautomaten (Übersicht)

**Contact-FSM:**
```
INVITED ─send/recv ContactCard─▶ PENDING ─AckEstablished─▶ ESTABLISHED
   │                                                          │
   │                                              ┌── SMP ok / QR ──▶ VERIFIED/CONFIRMED
   │                                              └── SMP fail ─────▶ (bleibt UNVERIFIED, Warnung)
   └────────────────────────────── revoke ──────────────────▶ REVOKED (terminal)
```

**Descriptor/Presence:** `PUBLISHED(epoch) ─revoke─▶ REPUBLISHING(epoch+1) ─done─▶ PUBLISHED(epoch+1)`

**Delivery:** siehe §9.4.

---

## 15. Offene Implementierungsfragen (Spikes für Phase 0)

| # | Frage | Warum kritisch |
|---|---|---|
| S1 | Arti-Reifegrad für Onion-Service **mit Client-Auth** | Bestimmt Tor-Stack-Wahl; C-tor-Interim braucht Sandbox |
| ~~S2~~ | **Entschieden (GATE-2 / ADR-17):** Primärgerät-Modell. Paarweiser Multi-Device-Ratchet ist verworfen — er verliert strukturell Nachrichten. Siehe §9.3 | — |
| S3 | Descriptor-Republish-Latenz bei Revocation | Zeitfenster, in dem ein revozierter Kontakt noch verbindet |
| S4 | Randomisierte Publikation vs. Tor-HSDir-Timing | Präsenzschutz nur wirksam, wenn HSDir-Upload-Muster nicht doch korreliert |
| S5 | Akku unter Dauer-Onion + Snowflake + Mesh-Beacons | Praktische Tragfähigkeit auf Mobil |
| S6 | Invitation-Größe mit PQ-Prekeys vs. QR-Kapazität | Ob QR reicht oder Link/NFC nötig |
| S7 | CBOR-Determinismus über alle Plattform-Bindings | Signatur-Konsistenz IK↔Descriptor |

---

## 16. Verhältnis zum Gesamtkonzept

Diese Spec konkretisiert §2.1–2.8 und §2.10 des Gesamtkonzepts. Nicht abgedeckt und weiterhin dort verbindlich: Ununterscheidbarkeit/Anonymitätsset (§2.9), Lieferkette (§2.11), Plattform-Einschränkungen (§2.12), iOS-Sonderfall (§6). Alle in Anhang A des Gesamtkonzepts verworfenen Ansätze bleiben verworfen.
