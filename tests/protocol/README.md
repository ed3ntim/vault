# Modellbasierte Protokolltests

Normativ: `spec/engineering-setup.md` §3.2 — „Modellbasierte Tests der FSMs
(Contact, Delivery, Group)". Gate G-2.

## Zu modellierende Zustandsautomaten

| FSM | Spec |
|---|---|
| Contact | `spec/protokoll-spec.md` §14, §5 (Handshake), §7 (Verifikation) |
| Delivery | `spec/protokoll-spec.md` §9.4 — Status `delivered` **nur** nach echtem E2E-ACK |
| Group | `spec/gruppen-spec.md` §8 |

## Weitere Pflichttests aus §3.2

- **Multi-Device:** randomisierte 10.000-Lauf-Suite aus Spike S2 als
  Regressionstest — 0 Verluste, 0 Duplikate, Konvergenz < 60 s,
  `skipped_message_keys` < 1000 pro Session.

Derzeit leer: die FSMs sind spezifiziert, aber noch nicht implementiert.
