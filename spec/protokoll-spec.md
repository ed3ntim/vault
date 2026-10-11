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
| `HMAC(k, m)` | HMAC-SHA-256 (RFC 2104; §9.3, §10, §13; kein eigenes Verfahren, gleiche Hash-Basis wie `HKDF`) |
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
  disappearing_ttl            // Default der Anzeigefrist (§8.2), keine Zustellfrist
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
Payload {
  msg_uid: 16B                                            // Nachrichten-Identität, s.u.
  body: PayloadBody
}

enum PayloadBody {
  Text { body, disappear_after }                          // Anzeigefrist, §8.2
  Attachment { key, size, chunk_count, manifest_hash }   // Chunks separat, XChaCha20
  Ack { ref_uid }                                         // setzt Status "delivered"
  Receipt { ref_uid, kind: DELIVERED|READ }               // READ opt-in
  ContactCard { ... }                                     // §5
  DeviceListUpdate { list, sig }
  SyncRecord { ... }                                      // Multi-Device (§9)
  GroupCtrl { ... }                                       // eigene Spec
  RevocationNotice { ... }                                // §11
}
```

### 8.1 Nachrichten-Identität und Dedup-Schlüssel

Es gibt **zwei** Bezeichner mit klar getrennter Aufgabe. Sie sind nicht austauschbar.

**`msg_uid`, Identität der Nachricht.** 16 B, vom Sender **einmal** bei der Komposition aus dem CSPRNG gezogen und danach unverändert über alle Zustellversuche, Neuverschlüsselungen, Zielgeräte, Transporte und Ratchet-Schritte hinweg. `msg_uid` liegt im AEAD-geschützten Klartext und erscheint **nie** auf der Wire. Jede Payload trägt genau eine `msg_uid`, auch `Ack` und `Receipt`; diese verweisen mit `ref_uid` auf die `msg_uid` der quittierten Nachricht.

**`env_ref = H(dr_header ‖ ciphertext)`, Referenz auf genau ein Chiffrat.** Deterministisch, kollisionsresistent, rein lokal gebildet, nie übertragen. `env_ref` identifiziert einen **Envelope**, keine Nachricht: dieselbe Nachricht an ein anderes Zielgerät neu verschlüsselt hat eine andere `env_ref`. `env_ref` ist deshalb **kein** Dedup-Schlüssel (Befund F-2, ADR-17); ihre einzige Verwendung ist die lokale Zuordnung „welches Chiffrat liegt in der Warteschlange" (§9.2). Im Envelope-Cache (§9.3) tritt dieselbe Größe **geschlüsselt** als `env_tag` auf; ein roher Hash wird dort nicht gespeichert (ADR-21).

**Dedup-Schlüssel ist `(compartment_id, contact_id, msg_uid)`.** Er ist geräteübergreifend stabil, weil `msg_uid` weder von der Verschlüsselung noch vom Zielgerät abhängt. Der Empfänger führt je Kontakt-Session einen Dedup-Store über `msg_uid`; eine bereits enthaltene `msg_uid` wird **nicht** erneut in den Verlauf, nicht in die UI und nicht in ein `SyncRecord` übernommen, wohl aber nach §9.3 quittiert. Der Store fasst [`MAX_DEDUP_UIDS`] = 2048 Einträge je Session und verdrängt bei Überlauf den Eintrag mit der ältesten Einfügereihenfolge (FIFO). Verdrängen statt Ablehnen, weil ein voller Store sonst jede weitere Nachricht der Session blockiert; dieselbe Politik gilt aus demselben Grund im Skipped-Message-Key-Store (ADR-19). Die Wiederholungsschranke in §9.2 stellt sicher, dass kein Sender länger wiederholt, als der Store zurückreicht.

Der in `spec/gruppen-spec.md` (§Transcript-Hash) verwendete `msg_id = H(ct)` ist eine gruppenlokale Kettengröße und **nicht** dieser Dedup-Schlüssel; er bleibt unverändert und wird nicht auf 1:1-Sessions angewandt.

`msg_uid` ist zufällig und nicht aus dem Inhalt abgeleitet: eine Ableitung aus dem Klartext erlaubte einem Angreifer, der den vermuteten Klartext kennt, dessen Existenz zu bestätigen. Der Dedup-Schlüssel exponiert damit nichts auf der Wire und schafft keine geräteübergreifende Verkettbarkeit für Dritte (A1/A2/A3 im Threat Model); verkettbar ist er ausschließlich für die beiden Sitzungsteilnehmer, denen der Klartext ohnehin vorliegt.

### 8.2 Anzeigefrist und Zustellfrist

**Zwei Fristen mit getrennter Aufgabe. Sie werden nie miteinander verrechnet.**

**`disappear_after`, Anzeigefrist.** Wie lange eine zugestellte Nachricht auf den Geräten beider Seiten sichtbar bleibt. Nutzerseitig einstellbar, Default je Kontakt aus `disappearing_ttl` (§3). Die Frist läuft **beim Empfänger ab erfolgreicher Entschlüsselung** (§9.3 Regel 1) und **beim Sender ab dem Eintreffen des `Ack`**. Sie läuft nicht, solange eine Nachricht in der Ausgangswarteschlange liegt, und sie beendet keinen Zustellversuch.

**`queue_ttl`, Zustellfrist.** Wie lange der Sender einen unzustellbaren Envelope wiederholt: **7 Tage**, einheitlich für **alle** Payload-Typen, nicht konfigurierbar, unabhängig von `disappear_after` (§9.2, §9.4).

Warum getrennt:
- Ein kurzer Selbstlösch-Default würde sonst die Zustellung abbrechen, obwohl der Empfänger nur offline war. Das erzeugte genau die Falschmeldung, die §9.4 und die Zusage zu G8 (`threat-model.md`) ausschließen.
- Eine an `disappear_after` gekoppelte Zustellfrist wäre **beobachtbar**: der Wiederholungsverkehr endete je nach Nutzereinstellung früher oder später und verriete die Einstellung an einen Netzbeobachter (A1/A2). `queue_ttl` ist deshalb Teil des einheitlichen, nicht konfigurierbaren Netzprofils (§2.9 Gesamtkonzept, TR-5).
- Erreicht ein Envelope die Zustellfrist, wird er als `EXPIRED` samt Nutzlast gelöscht (§9.2). Eine nie zugestellte Nachricht mit kurzer Anzeigefrist verschwindet damit ohnehin, nur ehrlich sichtbar als „nicht zugestellt" statt still.

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

**Wiederholung.** Die Ausgangswarteschlange hält den **fertigen Envelope**. Ein Zustellversuch an dasselbe Zielgerät wiederholt genau diese Bytes; neu verschlüsselt wird ausschließlich beim Wechsel des Zielgeräts. `msg_uid` (§8.1) bleibt in beiden Fällen gleich, `env_ref` ändert sich bei Neuverschlüsselung.

**Abbruchschranke (Befund F-3).** Die Wiederholung endet, sobald eines eintritt:
1. Ein `Ack` mit `ref_uid == msg_uid` trifft ein → `DELIVERED`.
2. Die `queue_ttl` läuft ab → `EXPIRED` (§9.4). Sie beträgt **7 Tage**, gilt für **jeden** Payload-Typ gleich und wird beim Einstellen in die Warteschlange gesetzt. Die Anzeigefrist `disappear_after` einer `Text`-Payload verkürzt sie **nicht** (§8.2).

Ohne Schranke 2 wiederholt der Sender unbegrenzt, sobald der Envelope-Cache der Gegenseite (§9.3) den Eintrag verdrängt hat; genau das ist die Endlosschleife aus Befund F-3. 7 Tage entsprechen ~168 Sync-Fenstern (§10, `INTERVAL = 3600 s`); eine längere Frist erhöht nur die Zeit, in der ein unzustellbarer Envelope auf dem Gerät liegt. Mit `EXPIRED` werden Envelope und Nutzlast gelöscht, `msg_uid` bleibt bis zum Ende des Dedup-Fensters erhalten.

### 9.3 Empfang & Geräte-Rollen (Primärgerät-Modell, GATE-2 / ADR-17)

Der Double-Ratchet-Zustand einer Kontakt-Session existiert **nur auf dem Primärgerät**. Zweitgeräte halten keinen eigenen Ratchet-Zustand für Kontakte.

- **Empfang:** Nur das Primärgerät entschlüsselt eingehende Kontakt-Envelopes und treibt die Ratchet voran. Es setzt das E2E-ACK; `delivered` wird ausschließlich vom Primärgerät gesetzt.
- **Zweitgeräte sind Read-Through-Replikate:** Sie erhalten entschlüsselte Verläufe per `SyncRecord` über das Intra-Identity-Mesh, reichen aber eingehende Kontakt-Envelopes nur als **opake Bytes** ans Primärgerät weiter, ohne sie zu entschlüsseln.
- **Senden vom Zweitgerät:** als Send-Proxy über das Primärgerät. Ist das Primärgerät nicht erreichbar, zeigt das Zweitgerät ehrlich „nicht sendefähig" statt eine Ratchet-Operation zu simulieren.
- **Rollenwechsel** (Primärgerät verloren/gewechselt) ist ein eigener, noch ungetesteter Ablauf → Restrisiko **R-11**, Spike vor Phase 2.

**Envelope-Cache und Re-Ack (Befund F-3).** Ein Ack kann verlorengehen. Stellt der Sender denselben Envelope erneut zu, kann der Empfänger ihn **nicht mehr entschlüsseln**, weil der Message Key verbraucht ist. Damit das Paar nicht in eine Endlosschleife läuft, führt das **Primärgerät** je Kontakt-Session einen Envelope-Cache:
```
k_env    = HKDF(DR_X.RK_initial, "vault-envelope-cache")   // einmal je Session
env_tag  = HMAC(k_env, dr_header ‖ ciphertext)[0..16]      // lokal, nie auf der Wire
Cache:     env_tag → msg_uid                               // je Session, keine Klartexte
```
Regeln, verbindlich:
1. **Nach erfolgreicher Entschlüsselung:** `env_tag → msg_uid` eintragen, `msg_uid` in den Dedup-Store (§8.1) aufnehmen, `Ack { ref_uid = msg_uid }` senden.
2. **Entschlüsselung schlägt fehl und `env_tag` ist im Cache:** Der Envelope gilt als bereits empfangen. Das Primärgerät antwortet mit einem **frisch verschlüsselten** `Ack { ref_uid = msg_uid }` aus dem aktuellen Sendezustand. Kein erneuter Entschlüsselungsversuch, kein Verlaufseintrag, kein `Receipt`, kein `SyncRecord`. Ein gespeichertes altes Ack-Chiffrat wird **nie** erneut gesendet (Replay, A7/G1).
3. **Entschlüsselung schlägt fehl und `env_tag` ist nicht im Cache:** verwerfen, ohne jede Antwort auf der Wire. Es wird kein Fehler und kein Statuscode zurückgegeben; eine unterscheidbare Antwort wäre ein Orakel für A7 und A4.
4. **Ratenbegrenzung:** höchstens [`MAX_REACK_PER_ENTRY`] = 5 Re-Acks je Cache-Eintrag und Stunde; darüber hinausgehende Wiederholungen werden nach Regel 3 behandelt. Re-Acks unterliegen demselben Ack-Zeitpunkt und Jitter wie reguläre Acks (GATE-3), damit ein autorisierter Kontakt sie nicht als feineres Präsenzsignal nutzt (A4/G3).
5. **Schranke:** [`MAX_ENV_CACHE`] = 2048 Einträge je Session, Verdrängung des ältesten Eintrags nach Einfügereihenfolge (FIFO), damit ein voller Cache die Session nicht blockiert; gleiche Politik wie im Skipped-Message-Key-Store (ADR-19). Ein verdrängter Eintrag fällt unter Regel 3; die Abbruchschranke in §9.2 beendet die Wiederholung senderseitig.
6. Der Cache enthält **kein** Schlüsselmaterial und keinen Klartext. `k_env` und der Cache werden bei Revocation (§11) mit der Session gelöscht (`zeroize`). Zweitgeräte führen keinen Envelope-Cache; sie reichen opake Bytes weiter und quittieren nie.
7. **Persistenz:** Cache und `k_env` liegen in der verschlüsselten Session-Ablage (`vault-storage`, SQLCipher) und überleben Neustarts; sonst fiele nach jedem App-Start jeder Wiederholungsversuch unter Regel 3 und eine gelesene Nachricht liefe beim Sender in `EXPIRED` (§9.4). Der Cache wird **nicht** an Zweitgeräte repliziert und nie exportiert.

`env_tag` ist geschlüsselt statt roh gehasht: ein roher Hash über den Envelope wäre für jeden berechenbar, der die Envelope-Bytes kennt, und erlaubte den Abgleich gegen einen erbeuteten Cache. Mit `k_env` ist der Cache ohne Sitzungsgeheimnis nicht prüfbar.

**Begründung:** Der Double Ratchet ist ein Zwei-Parteien-Protokoll; sein Sendezustand ist nicht über mehrere Geräte replizierbar. Die frühere Fassung (paarweiser Multi-Device-Ratchet) verlor strukturell Nachrichten (Spike S2: 4,15 % untere Schranke) und ist verworfen.

### 9.4 Zustellstatus-FSM
```
QUEUED ──attempt──▶ ATTEMPTING ──Ack──▶ DELIVERED ──Receipt──▶ READ
   ▲                    │
   └── kein reachable ──┴─▶ WAITING ──(Sync-Fenster/Erreichbarkeit)──▶ ATTEMPTING
                            │
                            └── queue_ttl abgelaufen ───────▶ EXPIRED (terminal)
```
UI zeigt `WAITING` als „wartet auf Erreichbarkeit" — nie „zugestellt". `EXPIRED` zeigt die UI als „nicht zugestellt"; der Zustand ist terminal, es folgt kein weiterer Versuch. `DELIVERED` setzt ausschließlich das Primärgerät nach einem echten E2E-`Ack` (§9.3), auch dann, wenn das Ack ein Re-Ack nach §9.3 Regel 2 ist: quittiert wird eine nachweislich einmal entschlüsselte Nachricht. Der Übergang nach `EXPIRED` hängt allein an der einheitlichen Zustellfrist `queue_ttl`, nie an der Anzeigefrist `disappear_after` (§8.2).

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
Die Intro-Point-Rotation (Schritt 2–3) ist von Vault **erzwungen**, nicht von der Transportschicht vorausgesetzt (ADR-15). Eine Revocation gilt erst als wirksam, wenn Rotation und Descriptor-Neuveröffentlichung bestätigt sind. Bis dahin zeigt die UI „Trennung läuft", nicht „getrennt" — dieselbe Ehrlichkeitsregel wie bei `delivered` (§9.4). Der revozierte Kontakt kann bis zur bestätigten Rotation über zwischengespeicherte Intro-Points noch verbinden; dieses Fenster misst Spike S3.

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
