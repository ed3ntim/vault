//! `Envelope` — Aussenhuelle einer zugestellten Nachricht.
//!
//! Normativ: `spec/protokoll-spec.md` §8 (Session & Messaging) und §9
//! (Zustellung, Multi-Device-Routing).
//!
//! Die Huelle ist fuer `vault-transport` opak: die Transportschicht kennt
//! nach `spec/engineering-setup.md` §2 keine Klartext-Payloads.
//!
//! Status: Geruest. Der Decoder folgt mit Sprint 0 #3. Bis dahin deckt das
//! Fuzz-Target `envelope` die gemeinsame Parserbasis ab.
