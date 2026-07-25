//! `Invitation` — Kontaktaufbau out-of-band (CT-1).
//!
//! Normativ: `spec/protokoll-spec.md` §4 — Felder `v`, `inviter_ik_ed_pub`,
//! `inviter_ik_x_pub`, `compartment{onion_addr, osk_ed_pub, cross_sig,
//! ca_priv}`, `prekey_bundle{spk_x_pub, spk_sig, pqspk_ek, pqspk_sig,
//! opk_x_pub?, pqopk_ek?}`, `invite_nonce` (16 B), `expires_at`, `sig`.
//! Einmalig, kurzlebig, replay-fest. Groesse ~400–600 B (Spike S6:
//! QR-Version <= 20).
//!
//! Status: Geruest. Der Decoder folgt mit Sprint 0 #3. Bis dahin deckt das
//! Fuzz-Target `invitation` die gemeinsame Parserbasis ab
//! ([`crate::cbor`], [`crate::lenprefix`]).
