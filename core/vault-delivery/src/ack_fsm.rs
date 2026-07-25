//! Zustellstatus-FSM. Status delivered ausschliesslich nach echtem E2E-ACK (DL-5).
//!
//! Normativ: `spec/gesamtkonzept.md` §2.6, `spec/protokoll-spec.md` §9.4
//!
//! Status: Geruest. Ein Status delivered ohne empfangenes ACK ist nach CLAUDE.md verboten.
