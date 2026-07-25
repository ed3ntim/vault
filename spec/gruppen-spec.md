# Vault Messenger — Gruppen-Spezifikation

**Ergänzt §12 der Protokoll-Spezifikation. Normativ für Gruppenerstellung, Mitgliederverwaltung, Ordnung, Zustellung und Equivocation-Erkennung.**

Notation und Primitive wie in der Protokoll-Spec (§1). Alle Gruppennachrichten laufen über bestehende 1:1-Kanäle bzw. gruppen-eigene Kompartimente — es gibt auch hier keine Infrastruktur.

---

## 1. Zwei Modi

| | **MLS-Modus** (Standard) | **Pairwise-Fanout** (Hochrisiko) |
|---|---|---|
| Verschlüsselung | MLS (RFC 9420), gemeinsamer Gruppenschlüssel | N paarweise Double-Ratchet-Sessions |
| Skalierung | bis ~50 Mitglieder praktikabel | bis ~8 Mitglieder |
| Kosten pro Nachricht | 1× Verschlüsselung, N−1 Zustellungen | N−1 Verschlüsselungen + Zustellungen |
| Gruppen-Metadatenpunkt | Peer-Sequencer sieht Epochen-Timing & Gruppengröße | **keiner** |
| Forward Secrecy / PCS | MLS-Epochen-Rekey | pro Paar-Ratchet |
| Mitgliedschaft | kryptografisch im Ratchet-Tree | nur Konvention + Transcript |

Die Modus-Wahl erfolgt bei Gruppenerstellung und ist danach fest (kein Wechsel — ein Wechsel würde Zustand und Verifikation invalidieren).

---

## 2. Gemeinsame Voraussetzungen

### 2.1 Nur bestehende Kontakte
Ein Mitglied kann nur hinzugefügt werden, wenn der Hinzufügende bereits eine **etablierte 1:1-Session** mit ihm hat. Grund: Ohne Verzeichnis existiert kein Weg, ein KeyPackage oder eine Erreichbarkeit von Fremden zu beziehen.

Konsequenz und bewusstes Designmerkmal: **Gruppen wachsen entlang existierender, verifizierter Vertrauensbeziehungen** — es gibt keine anonymen Beitritte, keine öffentlichen Gruppenlinks, keine External Commits.

### 2.2 Gruppen-Kompartiment
Für jede Gruppe legt jedes Mitglied ein **gruppen-gebundenes Kompartiment** an (bzw. nutzt ein für Gruppen reserviertes) und stellt jedem anderen Mitglied eine **gruppen-spezifische Client-Auth-Credential** aus.

```
on join_group(g):
    c_g = ensure_compartment(scope = GROUP, group_id = g)
    for each member m in g:
        CA_{c_g, m} = X25519.keygen()
        authorize(c_g, m, CA.pub)
        send CA.priv to m over 1:1 channel     // DR-verschlüsselt
```

Damit gilt: Gruppenmitglieder erhalten **keinen** Zugriff auf die persönlichen Kompartimente. Ein kompromittiertes Gruppenmitglied lernt die Gruppen-Erreichbarkeit, nicht das übrige Kontaktnetz. Bei Entfernung wird ausschließlich die gruppen-gebundene Credential revoziert (Protokoll-Spec §11).

### 2.3 Trennung von Handshake und Anwendungsnachrichten
Der zentrale Kunstgriff dieser Spezifikation:

- **Handshake-Nachrichten** (Proposals, Commits) benötigen eine **lineare Ordnung** → Peer-Sequencer (§4).
- **Anwendungsnachrichten** benötigen sie **nicht** — sie sind unter dem Epochenschlüssel verschlüsselt und innerhalb einer Epoche reihenfolgetolerant → **direkter Fan-out** an alle Mitglieder, ohne Sequencer.

Wirkung: Der Sequencer sieht nur Epochenwechsel — nicht das Gesprächsaufkommen, nicht Nachrichtengrößen, nicht wer wann schreibt. Sein Metadatenzugriff schrumpft auf ein Minimum.

---

## 3. MLS-Modus

### 3.1 Zustand
```
Group {
  group_id: 32B                  // Zufall bei Erstellung
  mode: MLS
  mls_state: RatchetTree, epoch, GroupContext, confirmed_transcript_hash,
             interim_transcript_hash, epoch_secrets
  members: [{ contact_id, leaf_index, ik_ed_pub }]
  compartment_id                 // gruppen-gebunden (§2.2)
  sequencer: { member_id, term }
  pending_commits: []
  epoch_attestations: Map<member_id, SignedAttestation>   // §5
}
```

### 3.2 KeyPackage-Bezug ohne Verzeichnis
MLS benötigt für `Add` ein **KeyPackage** des Beitretenden. Ohne Server:

```
Alice will Bob hinzufügen:
  Alice ──(1:1 DR)──▶ Bob : KeyPackageRequest { group_id_blinded }
  Bob   ──(1:1 DR)──▶ Alice: KeyPackage { init_key, leaf_node, capabilities,
                                          lifetime, sig_by_IK_Bob }
```
- KeyPackages sind **einmalig** (`init_key` wird nach Verbrauch verworfen) und **kurzlebig** (`lifetime`).
- `group_id_blinded = H(group_id ‖ nonce)` — Bob erfährt bei der Anfrage noch nicht, um welche Gruppe es geht, falls er ablehnt.
- Bobs KeyPackage ist von seiner Identität `IK` signiert → das Leaf im Ratchet-Tree ist an dieselbe Identität gebunden, die Alice bereits 1:1 verifiziert hat. **Kein neuer Vertrauensanker.**

### 3.3 Gruppenerstellung
```
1. group_id ← 32B Zufall; mode = MLS
2. mls_state = MLS.create_group(group_id, own_leaf)
3. für jedes Startmitglied: KeyPackage beziehen (§3.2)
4. Add-Proposals + Commit → Epoche 1
5. Welcome je Mitglied über dessen 1:1-Kanal senden (DR-verschlüsselt)
6. Gruppen-Kompartiment + Credentials austauschen (§2.2)
7. Sequencer deterministisch bestimmen (§4.1)
```
Das **Welcome** enthält den verschlüsselten Gruppen-Secret-Teil und läuft ausschließlich über den bereits authentisierten 1:1-Kanal — kein separater Vertrauensschritt nötig.

### 3.4 Anwendungsnachricht (Fan-out)
```
send_group_message(g, plaintext):
    ct = MLS.protect(g.mls_state, plaintext)      // epoch-gebunden
    frame = GroupFrame {
        group_id, epoch, ct,
        transcript_hash = g.mls_state.confirmed_transcript_hash,
        msg_id = H(ct)
    }
    for m in g.members \ self:
        deliver_via_group_compartment(m, frame)   // Tor, Fan-out
        // bei Nichterreichbarkeit: persistente Ausgangswarteschlange (Protokoll-Spec §9)
```
- Empfänger prüft `epoch` und `transcript_hash` gegen den eigenen Zustand. Abweichung → §5.
- Zustellung nutzt dieselbe Queue-/Retry-/ACK-Maschinerie wie 1:1 (`WAITING`-Status statt Falschmeldung).
- Nachrichten aus einer **älteren** Epoche werden nur akzeptiert, solange deren Secrets noch im Retention-Fenster liegen (Default: eine Epoche zurück), danach verworfen.

### 3.5 Mitgliedschaftsänderung
```
add_member(g, X):    KeyPackage(X) → Add-Proposal → Commit → epoch+1 → Welcome an X
remove_member(g, X): Remove-Proposal → Commit → epoch+1
                     + revoke_group_credential(X)   // Protokoll-Spec §11
```
**Kein Ghost-Member:** Mit dem Commit auf `epoch+1` besitzt X die neuen Epochen-Secrets nicht mehr — kryptografisch sofort wirksam für jedes Mitglied, das den Commit verarbeitet hat.

Restrisiko: Mitglieder, die den Commit noch nicht erhalten haben, senden weiter unter der alten Epoche und wären für X lesbar. Gegenmaßnahme:
```
Nach einem Remove-Commit gilt die Epoche erst als NUTZBAR, wenn
Attestations (§5) von ≥ quorum der verbleibenden Mitglieder vorliegen.
Bis dahin: UI-Status "Entfernung wird verteilt", Senden pausiert
(oder explizit als unsicher markiert).
```

---

## 4. Peer-Sequencer

### 4.1 Auswahl (deterministisch, ohne Wahlprotokoll)
```
sequencer(g, epoch) = argmin over m in reachable_members(g):
                          H(m.contact_id ‖ g.group_id ‖ epoch)
term = epoch
```
Jedes Mitglied berechnet dasselbe Ergebnis aus dem gemeinsamen Zustand. Die Rolle **rotiert automatisch mit jeder Epoche** → kein Mitglied akkumuliert dauerhaft Metadaten.

### 4.2 Aufgabe
```
Mitglied ──Commit(opak)──▶ Sequencer
Sequencer: vergibt seq_no, broadcastet SequencedCommit{seq_no, blob} an alle
```
Der Sequencer **entschlüsselt nichts**. Er sieht: Gruppengröße, Zeitpunkt eines Epochenwechsels, Blob-Größe (gepolstert).

### 4.3 Korrektheit ist nicht vom Sequencer abhängig
Entscheidender Punkt: **Der Sequencer ist eine Effizienz-, keine Korrektheitskomponente.**

```
Bei konkurrierenden Commits für dieselbe Epoche gilt deterministisch:
    winner = argmin H(commit_blob)
Alle Mitglieder wenden dieselbe Regel an; unterlegene Committer
verwerfen ihren Commit und wiederholen ihn gegen die neue Epoche (Re-Commit).
```
Ein bösartiger oder ausgefallener Sequencer kann damit **nicht forken** — er kann nur **verzögern**. Verzögerung ist über Attestation-Gossip (§5) und Timeout erkennbar.

### 4.4 Failover
```
Sequencer antwortet nicht innerhalb T_seq (Default 30 s):
    → nächstbestes Mitglied nach §4.1 übernimmt (term += 1)
    → Split-Brain unschädlich, da §4.3 unabhängig vom Sequencer entscheidet
```

### 4.5 Sequencer-loser Betrieb
In reinen Mesh-Situationen oder Kleingruppen kann der Sequencer entfallen: Commits werden direkt gefan-outet, Konflikte allein über §4.3 aufgelöst. Kosten: mehr Re-Commits bei gleichzeitigen Änderungen.

---

## 5. Equivocation-Erkennung (Attestation-Gossip)

Schützt gegen einen Sequencer oder ein Mitglied, das verschiedenen Empfängern verschiedene Historien zeigt.

```
Nach jedem Epochenwechsel signiert jedes Mitglied:
Attestation {
  group_id, epoch,
  confirmed_transcript_hash,     // aus MLS
  tree_hash,                     // Ratchet-Tree-Hash
  member_set_hash = H(sorted(member_ids)),
  sig = Sig(IK_member, ...)
}
```
- Attestations werden über die **1:1-Kanäle** verteilt (nicht über den Sequencer — sonst könnte er sie filtern).
- Jedes Mitglied vergleicht eingehende Attestations mit dem eigenen Zustand.
- **Divergenz bei gleicher `epoch`** → harter Alarm:
  ```
  UI: "Inkonsistenter Gruppenzustand erkannt — mögliche Manipulation"
  Aktion: Senden gesperrt, betroffene Epoche markiert,
          Nutzer zur Out-of-band-Klärung aufgefordert
  ```
- Ein Mitglied, das keine Attestations liefert, wird nach Timeout als **nicht bestätigt** markiert (zählt nicht zum Quorum in §3.5).

Damit ist Equivocation **erkennbar, nicht verhinderbar** — das ist unter serverlosen Bedingungen das erreichbare Maximum und entspricht dem Stand der Technik.

---

## 6. Pairwise-Fanout-Modus

Für kleine, hochsensible Gruppen (Richtwert ≤ 8). Es existiert **kein gemeinsamer Gruppenschlüssel und kein Gruppen-Metadatenpunkt**.

### 6.1 Aufbau
```
Group {
  group_id, mode: PAIRWISE
  members: [contact_id]           // lokale Sicht, keine kryptografische Bindung
  transcript: running hash chain
  compartment_id                  // gruppen-gebunden
}
```
Jede Nachricht wird **einzeln** über die bestehende 1:1-DR-Session an jedes Mitglied gesendet.

### 6.2 Transcript-Bindung gegen Content-Equivocation
Ohne gemeinsamen Zustand könnte ein Mitglied verschiedenen Empfängern verschiedene Inhalte senden. Gegenmittel:

```
H_0 = H(group_id)
H_i = H(H_{i-1} ‖ sender_id ‖ msg_id ‖ H(plaintext))

Jede Nachricht trägt: { seq_i, H_i, prev = H_{i-1} }
```
- Empfänger prüft `prev` gegen den eigenen Kettenkopf.
- **Gossip:** Mitglieder tauschen periodisch signierte `(seq, H_seq)`-Paare über ihre 1:1-Kanäle.
- Sendet ein Mitglied unterschiedliche Inhalte an verschiedene Empfänger, divergieren die Ketten → **Alarm wie in §5**.

### 6.3 Nebenläufigkeit
Gleichzeitige Nachrichten verschiedener Sender erzeugen konkurrierende Kettenglieder. Auflösung:
```
Bei gleichem seq: deterministische Ordnung nach (H(msg_id), sender_id).
Die Kette wird lokal linearisiert; alle Mitglieder konvergieren
auf dieselbe Reihenfolge, sobald sie beide Nachrichten haben.
```
Das ist ein CRDT-artiger Ansatz und hier **zulässig**, weil keine kryptografischen Epochen daran hängen (anders als bei MLS).

### 6.4 Mitgliedschaft
Mitgliedschaft ist Konvention, nicht Kryptografie: Ein Mitglied „entfernen" bedeutet, ihm nicht mehr zu senden und seine Gruppen-Credential zu revozieren. **Es gibt keine Garantie, dass alle Mitglieder dieselbe Mitgliederliste führen** — die Liste wird deshalb bei jeder Änderung als signierte `MemberSetUpdate` gefan-outet und Abweichungen in der UI angezeigt.

**Ehrlicher Trade-off:** Der Modus tauscht kryptografische Mitgliedschaftsgarantien gegen vollständige Metadatenfreiheit. Für kleine Zellen, in denen alle einander persönlich kennen, ist das die richtige Wahl; für größere Gruppen nicht.

---

## 7. Anhänge in Gruppen

```
key ← 32B Zufall
chunks = AEAD(key, ...)                    // wie 1:1
manifest = { size, chunk_count, manifest_hash }
```
- **MLS-Modus:** `key` und `manifest` in der MLS-geschützten Nachricht; Chunks werden per Fan-out an alle übertragen (jeder Empfänger holt sie vom Sender).
- **Pairwise-Modus:** `key` pro Empfänger separat in dessen DR-Session.
- Chunks tragen **keine** Gruppenkennung auf der Wire (Cross-Transport-Isolation, Protokoll-Spec §13).

---

## 8. Zustandsautomat

```
CREATING ──Commit epoch1──▶ ACTIVE
                              │
   ┌──────────────────────────┼───────────────────────────┐
   │                          │                           │
 EPOCH_PENDING          ATTESTATION_WAIT              INCONSISTENT
 (Commit unterwegs)     (Remove verteilt sich,        (Equivocation erkannt,
   │                     Senden pausiert)              Senden gesperrt)
   └──────────▶ ACTIVE ◀──────┘                           │
                              (nur nach manueller Klärung)┘

ACTIVE ──leave/removed──▶ LEFT (terminal, lokale Secrets zeroized)
```

---

## 9. Grenzen und Restrisiken

1. **Ein Mitglied ist immer ein Insider.** Ist ein Gruppenmitglied staatlich übernommen, kennt es Inhalte, Mitgliederliste und Timing. Kryptografisch unlösbar — gemindert durch kleine Gruppen, Pairwise-Modus, selbstlöschende Nachrichten (Default) und sofortige Revocation.
2. **Sequencer-Metadaten im MLS-Modus:** Epochen-Timing und Gruppengröße sind für den jeweiligen Sequencer sichtbar. Gemindert durch Rotation je Epoche, Padding und die Trennung von Anwendungsnachrichten (§2.3). Wer das nicht akzeptiert, nutzt Pairwise.
3. **Equivocation ist erkennbar, nicht verhinderbar** (§5) — Stand der Technik ohne vertrauenswürdigen Dritten.
4. **Fan-out-Kosten:** Zustellung skaliert linear mit der Gruppengröße; große Gruppen sind auf Mobilgeräten über Tor spürbar teuer. Daher die Größenrichtwerte in §1.
5. **Keine öffentlichen Gruppen.** Beitritt nur über bestehende Kontakte (§2.1) — bewusste Einschränkung, kein Defizit.

---

## 10. Offene Punkte (Spikes)

| # | Frage | Warum kritisch |
|---|---|---|
| G1 | MLS-Bibliothek in Rust: Reife von `openmls` für serverlosen Betrieb ohne DS | Bestimmt Machbarkeit des MLS-Modus |
| G2 | Fan-out-Performance über Tor bei 20–50 Mitgliedern (Circuit-Aufbau, Akku) | Entscheidet die realistische Obergrenze in §1 |
| G3 | Verhalten bei langfristig offline-gehenden Mitgliedern (Epochen-Retention, Nachholen) | Sonst schleichender Ausschluss inaktiver Mitglieder |
| G4 | Quorum-Schwelle für §3.5 (Removal-Wirksamkeit) vs. Nutzbarkeit | Zu hoch → Gruppe blockiert; zu niedrig → Ghost-Fenster |
| G5 | Attestation-Volumen bei großen Gruppen (N² Gossip über 1:1-Kanäle) | Skalierungsgrenze der Equivocation-Erkennung |

---

## 11. Backlog-Ergänzung

| ID | Story | Prio |
|---|---|---|
| GR-1 | Gruppen-Kompartiment + gruppen-gebundene Credentials | P1 |
| GR-2 | KeyPackage-Austausch über 1:1-Kanäle | P1 |
| GR-3 | MLS-Gruppe erstellen, Welcome über 1:1 zustellen | P1 |
| GR-4 | Anwendungsnachrichten per Fan-out (ohne Sequencer) | P1 |
| GR-5 | Peer-Sequencer mit deterministischer Auswahl & Rotation | P1 |
| GR-6 | Deterministische Commit-Konfliktauflösung (§4.3) | P1 |
| GR-7 | Attestation-Gossip + Inkonsistenz-Alarm | P1 |
| GR-8 | Quittierte Removals mit Quorum (§3.5) | P1 |
| GR-9 | Pairwise-Fanout-Modus inkl. Transcript-Kette | P2 |
| GR-10 | Gruppen-Anhänge | P2 |
