//! `GroupFrame` — Gruppen-Handshake- und Anwendungsrahmen.
//!
//! Normativ: `spec/protokoll-spec.md` §12 (Gruppen-Schnittstelle),
//! `spec/gruppen-spec.md` §2.3 (Trennung von Handshake und
//! Anwendungsnachrichten), §3.4, §4.2 (der Sequencer ordnet ausschliesslich
//! opake Blobs).
//!
//! Status: Geruest. Der Decoder folgt mit Sprint 0 #3. Bis dahin deckt das
//! Fuzz-Target `group_frame` die gemeinsame Parserbasis ab.
