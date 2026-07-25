//! Tor-Transport: Onion-Service mit Pflicht-Client-Auth (TR-1).
//!
//! Normativ: `spec/gesamtkonzept.md` §2.5; ADR-02, ADR-03; Spike S1
//! (`spec/phase0-spikeplan.md`) entscheidet Arti vs. C-tor sandboxed.
//!
//! Status: Geruest. Ein Betrieb *ohne* Client-Auth ist nach S1 ausdruecklich
//! kein zulaessiger Fallback und wird hier nicht implementiert.
