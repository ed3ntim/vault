//! Spike S3 — Prototyp der erzwungenen Intro-Point-Rotation.
//!
//! Normative Grundlage:
//!
//! `spec/protokoll-spec.md` §11 (Revocation, granular):
//! ```text
//! c = X.compartment_id
//! 1. compartment[c].authorized_clients.remove(X.contact_id)
//! 2. compartment[c].intro_point_epoch += 1
//! 3. tor: rotate_intro_points(onion_c); republish_descriptor(onion_c)
//!         -> X kann neuen Descriptor nicht mehr entschluesseln,
//!            alte Intro-Points tot
//! 4. mesh_visibility.remove(X)
//! 5. drop DR_X, purge session keys (zeroize)
//! 6. replicate RevocationNotice an eigene Geraete (SyncRecord)
//! ```
//!
//! ADR-15: die Rotation ist von Vault erzwungen, nicht von der Transportschicht
//! vorausgesetzt; eine Revocation gilt erst als wirksam, wenn Rotation und
//! Descriptor-Neuveroeffentlichung bestaetigt sind.
//!
//! Dies ist Wegwerfcode fuer eine Messung, kein Produktionscode.

#![forbid(unsafe_code)]

pub mod desc;
pub mod stats;

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use tor_llcrypto::pk::curve25519;
use tor_netdoc::doc::hsdesc::IntroPointDesc;

/// Lokaler Kontaktbezeichner (im Produktivsystem `H(ik_ed_pub)`).
pub type ContactId = u32;

/// Fehler des Prototyps. Bewusst grob — der Prototyp misst, er produziert nicht.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotError {
    /// Der zu revozierende Kontakt ist im Kompartiment nicht autorisiert.
    UnknownContact(ContactId),
    /// Die Transportschicht hat einen Schritt nicht bestaetigt.
    Transport(&'static str),
    /// Descriptor konnte nicht gebaut werden (z. B. Leerfall, siehe ADR-16 §6).
    Descriptor(String),
}

/// Zustand der Revocation-Anzeige in der UI (ADR-15, Punkt 3).
///
/// `Running` heisst „Trennung laeuft", `Effective` heisst „getrennt".
/// Ein Sprung nach `Effective` ohne bestaetigte Publikation waere dieselbe
/// Klasse von Unehrlichkeit wie ein `delivered` ohne E2E-ACK (`CLAUDE.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationState {
    Idle,
    Running,
    Effective,
    Failed,
}

/// Reihenfolge von Abriss und Neuaufbau der Introduction Points.
///
/// Die Spec (§11 Schritt 3) legt sie nicht fest. Der Unterschied ist
/// sicherheitsrelevant und wird deshalb hier explizit gemacht und gemessen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationOrder {
    /// Erst alle alten Intro-Points abreissen, dann neue etablieren.
    /// Folge: der Revozierte verliert den Zugang sofort; der eigene Dienst ist
    /// fuer *alle* Kontakte offline, bis die neuen Intro-Points stehen.
    TeardownFirst,
    /// Erst neue Intro-Points etablieren, dann alte abreissen
    /// („make before break"). Folge: keine Erreichbarkeitsluecke, aber der
    /// Revozierte behaelt bis zum Abriss einen nutzbaren Pfad.
    MakeBeforeBreak,
}

/// Kompartiment-Ausschnitt nach `spec/protokoll-spec.md` §3.
pub struct Compartment {
    pub id: u8,
    /// `intro_point_epoch: u32` — erhoeht bei Revocation.
    pub intro_point_epoch: u32,
    /// Monoton wachsend; ein HSDir verwirft einen Descriptor mit nicht
    /// groesserem `revision-counter`.
    pub revision_counter: u64,
    /// `authorized_clients: Map<contact_id, CA_pub>`.
    pub authorized_clients: BTreeMap<ContactId, curve25519::PublicKey>,
    /// Aktuell etablierte Introduction Points.
    pub intro_points: Vec<IntroPointDesc>,
    /// Ist derzeit ein Descriptor veroeffentlicht?
    pub published: bool,
    /// §13: fuer wen ist ein Mesh-Beacon berechenbar.
    pub mesh_visibility: BTreeMap<ContactId, [u8; 32]>,
    /// Double-Ratchet-/Sessionmaterial je Kontakt (hier nur Attrappe zur
    /// Modellierung des Purge-Schritts).
    pub sessions: BTreeMap<ContactId, Vec<u8>>,
}

impl Compartment {
    pub fn new(id: u8) -> Self {
        Self {
            id,
            intro_point_epoch: 0,
            revision_counter: 0,
            authorized_clients: BTreeMap::new(),
            intro_points: Vec::new(),
            published: false,
            mesh_visibility: BTreeMap::new(),
            sessions: BTreeMap::new(),
        }
    }
}

/// Was die Transportschicht fuer die erzwungene Rotation leisten muss.
///
/// Die Aufteilung entspricht dem, was `spec/protokoll-spec.md` §11 Schritt 3
/// in einem Satz zusammenfasst. Sie ist hier getrennt, weil die Schritte
/// unterschiedlich lange dauern und **unterschiedliche** Wirkungen haben:
/// erst `withdraw_intro_points` entzieht dem Revozierten den Pfad,
/// erst `publish_descriptor` stellt die Erreichbarkeit fuer die uebrigen
/// Kontakte wieder her.
pub trait RotationTransport {
    /// Reisst die Introduction-Point-Circuits der angegebenen Epoche ab.
    /// Rueckgabe: Anzahl tatsaechlich abgerissener Intro-Points.
    fn withdraw_intro_points(&mut self, epoch: u32) -> Result<usize, RotError>;

    /// Etabliert `n` neue Introduction Points fuer die neue Epoche.
    fn establish_intro_points(
        &mut self,
        epoch: u32,
        n: usize,
    ) -> Result<Vec<IntroPointDesc>, RotError>;

    /// Baut und veroeffentlicht den Descriptor. Rueckgabe: Descriptor-Bytes.
    fn publish_descriptor(
        &mut self,
        epoch: u32,
        revision_counter: u64,
        authorized: &[curve25519::PublicKey],
        intro_points: &[IntroPointDesc],
    ) -> Result<Vec<u8>, RotError>;

    /// Nimmt den Dienst vom Netz (Leerfall: kein autorisierter Kontakt mehr,
    /// ADR-16 Punkt 6).
    fn unpublish(&mut self) -> Result<(), RotError>;
}

/// Zeitachse eines Revocation-Laufs. Alle Werte sind Abstaende zum Ausloeser.
#[derive(Debug, Clone, Copy, Default)]
pub struct RevocationTimeline {
    /// Schritt 1: Credential entzogen.
    pub t_credential_removed: Duration,
    /// Schritt 2: `intro_point_epoch += 1`.
    pub t_epoch_bumped: Duration,
    /// Schritt 3a: alte Introduction Points abgerissen.
    /// **Das ist der Zeitpunkt, an dem der Revozierte den Pfad verliert.**
    pub t_old_ipts_withdrawn: Duration,
    /// Schritt 3b: neue Introduction Points etabliert.
    pub t_new_ipts_established: Duration,
    /// Schritt 3c: Descriptor gebaut und veroeffentlicht.
    /// **Erst hier gilt die Revocation nach ADR-15 als wirksam**, und erst
    /// hier sind die uebrigen Kontakte wieder erreichbar.
    pub t_descriptor_published: Duration,
    /// Schritt 4: Mesh-Sichtbarkeit entzogen.
    pub t_mesh_removed: Duration,
    /// Schritt 5: Sessionmaterial geloescht.
    pub t_session_purged: Duration,
    /// Schritt 6: RevocationNotice an eigene Geraete repliziert.
    pub t_replicated: Duration,
    /// Gesamtdauer bis `Effective`.
    pub t_total: Duration,
    /// Erreichbarkeitsluecke des eigenen Dienstes fuer die uebrigen Kontakte.
    pub outage: Duration,
    /// Groesse des neu veroeffentlichten Descriptors.
    pub descriptor_bytes: usize,
    /// Zahl der abgerissenen Intro-Points.
    pub withdrawn: usize,
}

/// Ergebnis eines Laufs.
#[derive(Debug)]
pub struct RevocationOutcome {
    pub state: RevocationState,
    pub timeline: RevocationTimeline,
}

/// Fuehrt `spec/protokoll-spec.md` §11 aus.
pub fn revoke<T: RotationTransport>(
    comp: &mut Compartment,
    transport: &mut T,
    contact: ContactId,
    order: RotationOrder,
    num_intro_points: usize,
) -> Result<RevocationOutcome, RotError> {
    let t0 = Instant::now();
    let mut tl = RevocationTimeline::default();
    let mut _state = RevocationState::Running;

    // --- Schritt 1: Credential entziehen -------------------------------
    if comp.authorized_clients.remove(&contact).is_none() {
        return Err(RotError::UnknownContact(contact));
    }
    tl.t_credential_removed = t0.elapsed();

    // --- Schritt 2: intro_point_epoch += 1 -----------------------------
    let old_epoch = comp.intro_point_epoch;
    comp.intro_point_epoch = comp.intro_point_epoch.saturating_add(1);
    let new_epoch = comp.intro_point_epoch;
    tl.t_epoch_bumped = t0.elapsed();

    // --- Schritt 3: Rotation + Republish -------------------------------
    match order {
        RotationOrder::TeardownFirst => {
            tl.withdrawn = transport.withdraw_intro_points(old_epoch)?;
            tl.t_old_ipts_withdrawn = t0.elapsed();
            let ipts = transport.establish_intro_points(new_epoch, num_intro_points)?;
            comp.intro_points = ipts;
            tl.t_new_ipts_established = t0.elapsed();
        }
        RotationOrder::MakeBeforeBreak => {
            let ipts = transport.establish_intro_points(new_epoch, num_intro_points)?;
            comp.intro_points = ipts;
            tl.t_new_ipts_established = t0.elapsed();
            tl.withdrawn = transport.withdraw_intro_points(old_epoch)?;
            tl.t_old_ipts_withdrawn = t0.elapsed();
        }
    }

    // Leerfall: letzter Kontakt des Kompartiments revoziert.
    // ADR-16 Punkt 6: ein Kompartiment ohne autorisierte Kontakte wird
    // nicht publiziert (Arti erzeugt dort Bug/BadApiUsage, S1/T8).
    if comp.authorized_clients.is_empty() {
        transport.unpublish()?;
        comp.published = false;
        tl.t_descriptor_published = t0.elapsed();
        tl.descriptor_bytes = 0;
    } else {
        comp.revision_counter = comp.revision_counter.saturating_add(1);
        let clients: Vec<curve25519::PublicKey> =
            comp.authorized_clients.values().copied().collect();
        let bytes = transport.publish_descriptor(
            new_epoch,
            comp.revision_counter,
            &clients,
            &comp.intro_points,
        )?;
        comp.published = true;
        tl.descriptor_bytes = bytes.len();
        tl.t_descriptor_published = t0.elapsed();
    }

    // --- Schritt 4: Mesh-Sichtbarkeit ----------------------------------
    comp.mesh_visibility.remove(&contact);
    tl.t_mesh_removed = t0.elapsed();

    // --- Schritt 5: Sessionmaterial loeschen ---------------------------
    // Im Produktionscode mit `zeroize` (CLAUDE.md). Hier nur Ueberschreiben,
    // damit der Schritt in der Zeitachse auftaucht.
    if let Some(mut material) = comp.sessions.remove(&contact) {
        for b in material.iter_mut() {
            *b = 0;
        }
    }
    tl.t_session_purged = t0.elapsed();

    // --- Schritt 6: Replikation an eigene Geraete ----------------------
    // Nicht modelliert (Netzpfad, ADR-17 Primaergeraet). Zeitstempel bleibt
    // gleich dem vorigen Schritt; im Bericht als nicht gemessen ausgewiesen.
    tl.t_replicated = t0.elapsed();

    tl.t_total = t0.elapsed();
    tl.outage = match order {
        RotationOrder::TeardownFirst => {
            tl.t_descriptor_published.saturating_sub(tl.t_old_ipts_withdrawn)
        }
        RotationOrder::MakeBeforeBreak => Duration::ZERO,
    };

    _state = RevocationState::Effective;
    Ok(RevocationOutcome {
        state: RevocationState::Effective,
        timeline: tl,
    })
}
