//! `s5-eval` — Auswertung der Messreihen aus Spike S5
//! (`spec/phase0-spikeplan.md` §2, "S5 — Akkuverbrauch").
//!
//! Das Werkzeug rechnet aus Rohdaten eines Android-Geraets die drei
//! Erfolgskriterien des Spikes aus. Es erzeugt **keine** Messwerte und
//! extrapoliert nur, wenn ein Lauf kuerzer als 24 h war — und markiert das dann.
//!
//! Kein Netzzugriff, keine Dependencies, keine Telemetrie (ADR-14).

#![forbid(unsafe_code)]

pub mod batterystats;
pub mod csvlog;
pub mod history;
pub mod stats;
pub mod thermal;
pub mod verdict;
