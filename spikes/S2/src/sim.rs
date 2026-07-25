//! Ereignisgesteuerte Simulation des Multi-Device-Zustellmodells (Spike S2).
//!
//! Spec-Bezug:
//!   protokoll-spec.md §9.2 (deterministische Zielreihenfolge, Ack-Timeout,
//!   persistente Ausgangswarteschlange), §9.3 (Empfang & Geschwister-Sync),
//!   §9.4 (Zustellstatus-FSM: DELIVERED nur nach echtem E2E-Ack),
//!   §10 (Sync-Fenster), gesamtkonzept.md §2.6.
//!
//! Die Zeit ist **simuliert** (Einheit: Millisekunde). Es wird nie gewartet.

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use std::collections::{BinaryHeap, HashMap, HashSet};

use crate::crypto::{self, DerivedKeyRng, PublicKey, Ratchet};
use crate::vendor_dr::{CryptoProvider, DecryptError, Header};

/// Simulierte Zeit in Millisekunden.
pub type Time = u64;

/// Eine Sekunde simulierter Zeit.
pub const SEC: Time = 1_000;
/// Eine Minute simulierter Zeit.
pub const MIN: Time = 60 * SEC;
/// Eine Stunde simulierter Zeit.
pub const HOUR: Time = 60 * MIN;
/// Ein Tag simulierter Zeit.
pub const DAY: Time = 24 * HOUR;

/// Associated Data des Envelopes (Platzhalter fuer H(dr_header), §8).
const AD: &[u8] = b"vault-s2";

/// Maximal gleichzeitig unquittierte Nachrichten des Kontakts.
const MAX_INFLIGHT: usize = 256;
/// Voreinstellung fuer die maximalen Zustellversuche je Nachricht.
/// Danach bleibt die Nachricht dauerhaft WAITING (nie DELIVERED, §9.4).
pub const DEFAULT_MAX_ATTEMPTS: u32 = 30;
/// Raster fuer Wiederholungsversuche (Erreichbarkeitspruefung).
const TICK: Time = 10 * MIN;
/// Ack-Timeout, danach Status WAITING (§9.4).
const ACK_TIMEOUT: Time = 60 * SEC;
/// Abstand aufeinanderfolgender Nachrichten im selben Zustellversuch.
const MSG_SPACING: Time = 20;
/// Uebertragungszeit je SyncRecord im Geschwister-Batch (~512 B bei ~50 kB/s).
const SYNC_REC_MS: Time = 10;
/// Dauer eines Sync-Fensters (§10, Look-back/-ahead-Toleranz).
const SYNC_WINDOW: Time = 180 * SEC;
/// Grundraster der Sync-Fenster (§10: INTERVAL = 3600 s).
const SYNC_INTERVAL: Time = HOUR;

/// Welches Multi-Device-Modell simuliert wird.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Variant {
    /// Variante A: eine gemeinsame Kontakt-Session, `dr_delta` ueber das
    /// Geschwister-Mesh repliziert (protokoll-spec §9.3, Wortlaut).
    A,
    /// Variante A mit zusaetzlicher Reconciliation: bei erkannter Divergenz
    /// uebernimmt das Geraet mit hoeherer ID den Zustandssnapshot des
    /// Geraets mit niedrigerer ID (deterministischer kanonischer Zweig).
    AReconcile,
    /// Variante B: Primaergeraet haelt den kanonischen Zustand, Zweitgeraete
    /// sind Read-Through-Replikate mit Store-and-Forward/Send-Proxy.
    B,
    /// Variante A2 (informativ, nicht im Spike-Auftrag): je eigenem Geraet
    /// eine eigene Kontakt-Session; Geschwister-Sync traegt nur Klartext.
    A2,
}

impl Variant {
    /// Kurzname fuer Rohdaten.
    pub fn name(self) -> &'static str {
        match self {
            Variant::A => "A",
            Variant::AReconcile => "A-reconcile",
            Variant::B => "B",
            Variant::A2 => "A2",
        }
    }
}

/// Szenarioprofil nach phase0-spikeplan.md §2 (S2, Methode Punkt 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Profile {
    /// Gleichzeitiger Empfang auf mehreren Geraeten.
    Concurrent,
    /// Ein Geraet wochenlang offline.
    LongOffline,
    /// Netztrennung mitten im Ratchet (Geschwister-Link bricht weg).
    PartitionMidRatchet,
    /// Uhr-Drift zwischen den Geraeten.
    ClockDrift,
    /// Alle vier gleichzeitig.
    Mixed,
}

impl Profile {
    /// Kurzname fuer Rohdaten.
    pub fn name(self) -> &'static str {
        match self {
            Profile::Concurrent => "concurrent",
            Profile::LongOffline => "long-offline",
            Profile::PartitionMidRatchet => "partition-mid-ratchet",
            Profile::ClockDrift => "clock-drift",
            Profile::Mixed => "mixed",
        }
    }
    /// Alle Profile.
    pub fn all() -> [Profile; 5] {
        [
            Profile::Concurrent,
            Profile::LongOffline,
            Profile::PartitionMidRatchet,
            Profile::ClockDrift,
            Profile::Mixed,
        ]
    }
}

/// Envelope nach protokoll-spec §8 (ohne `transport_tag`, der fuer die
/// Zustelllogik bedeutungslos ist).
#[derive(Clone)]
pub struct Envelope {
    header: Header<PublicKey>,
    ct: Vec<u8>,
}

impl Envelope {
    /// `msg_id = H(dr_header ‖ ciphertext)` (protokoll-spec §8).
    fn msg_id(&self) -> [u8; 32] {
        crypto::h(&[
            self.header.dh.as_ref(),
            &self.header.n.to_le_bytes(),
            &self.header.pn.to_le_bytes(),
            &self.ct,
        ])
    }
}

fn pt_content(lid: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(37);
    v.push(0x01);
    v.extend_from_slice(&lid.to_le_bytes());
    v.extend_from_slice(&[0u8; 32]);
    v
}

fn pt_ack(lid: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(5);
    v.push(0x02);
    v.extend_from_slice(&lid.to_le_bytes());
    v
}

fn parse_pt(pt: &[u8]) -> Option<(u8, u32)> {
    let kind = *pt.first()?;
    let b = pt.get(1..5)?;
    let mut a = [0u8; 4];
    a.copy_from_slice(b);
    Some((kind, u32::from_le_bytes(a)))
}

/// Operation, die ein Geschwistergeraet nachvollziehen muss (`dr_delta`, §9.3).
#[derive(Clone)]
enum SyncOp {
    /// Empfangener Envelope inkl. Klartext-Kennung.
    Recv { env: Envelope, lid: u32 },
    /// Vom Geschwister gesendeter Ack-Envelope (Sendekette nachziehen).
    Sent { env: Envelope, lid: u32 },
    /// Nur Klartext (Varianten B und A2).
    Plain { lid: u32 },
}

/// Ein SyncRecord ueber das Intra-Identity-Mesh (§9.3).
#[derive(Clone)]
struct SyncRecord {
    from: usize,
    ops: Vec<SyncOp>,
    snapshot: Option<Box<Ratchet>>,
}

#[derive(Clone)]
enum Pkt {
    /// Kontakt -> eigenes Geraet.
    ToMe { env: Envelope, idx: u32, attempt: u32 },
    /// eigenes Geraet -> Kontakt.
    ToContact { env: Envelope },
    /// Geschwister-SyncRecord.
    Sync(SyncRecord),
    /// Variante B: Zweitgeraet leitet undurchsichtigen Envelope ans Primaergeraet weiter.
    Fwd { env: Envelope, from: usize },
}

enum EvKind {
    Compose(u32),
    Online(usize),
    Arrive { to: usize, pkt: Pkt },
    AckTimeout { idx: u32, attempt: u32 },
    Tick,
    DrainStart,
}

struct Ev {
    t: Time,
    seq: u64,
    kind: EvKind,
}

impl PartialEq for Ev {
    fn eq(&self, o: &Self) -> bool {
        self.t == o.t && self.seq == o.seq
    }
}
impl Eq for Ev {}
impl Ord for Ev {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        // BinaryHeap ist ein Max-Heap -> Ordnung umdrehen.
        o.t.cmp(&self.t).then(o.seq.cmp(&self.seq))
    }
}
impl PartialOrd for Ev {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}

/// Online-Zeitplan eines Knotens.
#[derive(Clone, Debug)]
struct Schedule {
    on: Vec<(Time, Time)>,
}

impl Schedule {
    /// Intervalle sind sortiert und disjunkt -> binaere Suche.
    fn online(&self, t: Time) -> bool {
        match self.on.binary_search_by(|(a, _)| a.cmp(&t)) {
            Ok(_) => true,
            Err(0) => false,
            Err(i) => self
                .on
                .get(i.saturating_sub(1))
                .map(|(_, b)| t < *b)
                .unwrap_or(false),
        }
    }

    /// Laenge der Offline-Luecke unmittelbar vor `t` (0, wenn `t` der Anfang
    /// des ersten Intervalls ist oder `t` nicht auf einen Intervallstart faellt).
    fn gap_before(&self, t: Time) -> Time {
        let idx = self.on.iter().position(|(a, _)| *a == t);
        match idx {
            Some(0) => t,
            Some(i) => self
                .on
                .get(i.saturating_sub(1))
                .map(|(_, b)| t.saturating_sub(*b))
                .unwrap_or(0),
            None => 0,
        }
    }
    fn starts(&self) -> Vec<Time> {
        self.on.iter().map(|(a, _)| *a).collect()
    }
    fn normalize(mut v: Vec<(Time, Time)>) -> Self {
        v.sort_unstable();
        let mut out: Vec<(Time, Time)> = Vec::with_capacity(v.len());
        for (a, b) in v {
            if b <= a {
                continue;
            }
            match out.last_mut() {
                Some(last) if a <= last.1 => {
                    if b > last.1 {
                        last.1 = b;
                    }
                }
                _ => out.push((a, b)),
            }
        }
        Self { on: out }
    }
}

/// Ausgangswarteschlangen-Eintrag des Kontakts (§9.2, gesamtkonzept §2.6).
struct OutMsg {
    lid: u32,
    /// Bei A/A-R/B einmalig verschluesselt und persistent (§2.6 Punkt 1).
    env: Option<Envelope>,
    delivered: bool,
    attempts: u32,
    in_flight: bool,
}

struct Contact {
    /// Variante A/A-R/B: genau eine Session. A2: je eigenem Geraet eine.
    dr: Vec<Ratchet>,
    rng: Vec<DerivedKeyRng>,
    queue: Vec<OutMsg>,
    pending: Vec<u32>,
    by_lid: HashMap<u32, u32>,
    in_flight: usize,
    max_skipped: usize,
    ack_decrypt_fail: usize,
}

struct MyDevice {
    id: usize,
    dr: Option<Ratchet>,
    rng: DerivedKeyRng,
    history: HashMap<u32, Time>,
    /// Envelope-Hash -> logische Nachrichten-ID (Wiederholungs-Ack ohne
    /// erneute Entschluesselung; siehe Bericht, Befund F-2).
    seen_env: HashMap<[u8; 32], u32>,
    pending_sync: Vec<Vec<SyncRecord>>,
    pending_fwd: Vec<Envelope>,
    pending_to_contact: Vec<Envelope>,
    max_skipped: usize,
    drift: i64,
}

/// Konvergenzsonde.
struct Probe {
    dev: usize,
    t0: Time,
    /// Noch fehlende logische Nachrichten-IDs.
    remaining: HashSet<u32>,
    done: Option<Time>,
    /// Erster Zeitpunkt >= `t0`, zu dem das Geraet **und** mindestens ein
    /// Geschwistergeraet gleichzeitig online sind. Erst ab hier kann das
    /// Protokoll ueberhaupt synchronisieren (serverlos, kein Zwischenspeicher).
    t_link: Option<Time>,
}

/// Ergebnis eines Laufs.
#[derive(Clone, Debug, Serialize)]
pub struct RunResult {
    /// Seed des Laufs.
    pub seed: u64,
    /// Variante.
    pub variant: &'static str,
    /// Szenarioprofil.
    pub profile: &'static str,
    /// Anzahl eigener Geraete.
    pub n_devices: usize,
    /// Latenzmultiplikator.
    pub latency_mult: u32,
    /// Anzahl gesendeter Nachrichten.
    pub n_msgs: usize,
    /// Nachrichten, die am Ende auf **keinem** eigenen Geraet vorliegen.
    pub lost: usize,
    /// (Geraet, Nachricht)-Paare, die am Ende fehlen, obwohl ein anderes
    /// Geraet sie hat (Konvergenzluecke).
    pub unconverged: usize,
    /// Doppelte Zustellungen, die die Deduplikation abfangen musste.
    pub dup_suppressed: usize,
    /// Davon jene, die `msg_id` nach §8 **nicht** erkannt haette (echte
    /// Duplikate bei woertlicher Spec-Umsetzung).
    pub dup_missed_by_msgid: usize,
    /// Maximale Anzahl gespeicherter Skipped Message Keys auf eigenen Geraeten.
    pub max_skipped_device: usize,
    /// dito auf der Kontaktseite.
    pub max_skipped_contact: usize,
    /// Anzahl Konvergenzsonden.
    pub probes: usize,
    /// Sonden, die bis Simulationsende konvergiert sind.
    pub probes_converged: usize,
    /// Sonden, die > 60 s brauchten.
    pub probes_over_60s: usize,
    /// Groesste gemessene Konvergenzzeit (ms).
    pub conv_max_ms: u64,
    /// Summe aller Konvergenzzeiten (ms), fuer Aggregation.
    pub conv_sum_ms: u64,
    /// Vom Kontakt verworfene Acks (Sendeketten-Kollision eigener Geraete).
    pub ack_dropped: usize,
    /// Erkannte Divergenzen der Sendekette zwischen eigenen Geraeten.
    pub send_divergence: usize,
    /// Fehlgeschlagene Entschluesselungen einer noch unbekannten Nachricht.
    pub decrypt_fail_new: usize,
    /// `SkipTooLarge` (MAX_SKIP = 1000 ueberschritten).
    pub skip_too_large: usize,
    /// `StorageFull` (MKS_CAPACITY = 2000 ueberschritten).
    pub storage_full: usize,
    /// Sendeversuche des Kontakts insgesamt.
    pub attempts: usize,
    /// Vom Kontakt als DELIVERED markierte Nachrichten (nur nach echtem Ack).
    pub delivered: usize,
    /// Zustellverzoegerung p95 (ms) vom Verfassen bis DELIVERED.
    pub delivery_p95_ms: u64,
    /// Groesste Zustellverzoegerung (ms).
    pub delivery_max_ms: u64,
    /// Anzahl replizierter SyncRecords.
    pub sync_records: usize,
    /// Wie oft die Versuchsobergrenze gezogen hat.
    pub attempt_cap_hits: usize,
    /// Nachrichten, die am Simulationsende nie quittiert wurden (Status
    /// WAITING, nie DELIVERED).
    pub undelivered_final: usize,
    /// Sonden mit gemessenem Geschwister-Link.
    pub link_probes: usize,
    /// davon konvergiert.
    pub link_converged: usize,
    /// davon > 60 s ab Linkverfuegbarkeit.
    pub link_over_60s: usize,
    /// groesste Konvergenzzeit ab Linkverfuegbarkeit (ms).
    pub link_conv_max_ms: u64,
    /// Summe der Konvergenzzeiten ab Linkverfuegbarkeit (ms).
    pub link_conv_sum_ms: u64,
    /// Histogramm der Konvergenzzeiten ab Linkverfuegbarkeit:
    /// [<1s, <5s, <15s, <60s, <300s, <3600s, >=3600s].
    pub link_hist: [usize; 7],
}

/// Konfiguration eines Laufs.
#[derive(Clone, Copy, Debug)]
pub struct RunCfg {
    /// Seed.
    pub seed: u64,
    /// Variante.
    pub variant: Variant,
    /// Profil.
    pub profile: Profile,
    /// Nachrichtenzahl.
    pub n_msgs: usize,
    /// Latenzmultiplikator (1 = Basisannahme).
    pub latency_mult: u32,
    /// Maximale Zustellversuche je Nachricht.
    pub max_attempts: u32,
}

/// Fuehrt einen vollstaendigen Lauf aus.
pub fn run(cfg: RunCfg) -> RunResult {
    Sim::new(cfg).execute()
}

struct Sim {
    cfg: RunCfg,
    rng: ChaCha20Rng,
    now: Time,
    seq: u64,
    q: BinaryHeap<Ev>,
    sched: Vec<Schedule>, // 0 = Kontakt, 1..=n = eigene Geraete
    contact: Contact,
    devs: Vec<MyDevice>,
    n_dev: usize,
    horizon: Time,
    drain_end: Time,
    p_flap: f64,
    p_sync_drop: f64,
    probes: Vec<Probe>,
    compose_at: HashMap<u32, Time>,
    delivered_at: Vec<u64>,
    r: RunResult,
}

impl Sim {
    fn new(cfg: RunCfg) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(cfg.seed);
        let n_dev = if cfg.variant == Variant::B {
            rng.gen_range(2..=3)
        } else {
            rng.gen_range(2..=3)
        };

        let horizon = 14 * DAY;
        let drain_end = horizon + 2 * DAY;

        // --- Sitzungsgeheimnisse ------------------------------------------
        let session_seed = crypto::h(&[&cfg.seed.to_le_bytes(), b"session"]);
        let sync_key = crypto::h(&[&session_seed, b"vault-sync-window"]);
        let contact_seed = crypto::h(&[&session_seed, b"contact-ratchet"]);
        let device_seed = crypto::h(&[&session_seed, b"device-ratchet"]);

        // --- Uhr-Drift ----------------------------------------------------
        let drift_max: i64 = match cfg.profile {
            Profile::ClockDrift | Profile::Mixed => 600_000, // +-10 min
            _ => 2_000,
        };

        // --- Zeitplaene ---------------------------------------------------
        let mut sched = Vec::with_capacity(n_dev + 1);
        sched.push(Schedule { on: Vec::new() }); // Platzhalter Kontakt
        for _ in 0..n_dev {
            sched.push(Schedule { on: Vec::new() });
        }

        let mut drifts = vec![0i64; n_dev];
        for (i, d) in drifts.iter_mut().enumerate() {
            *d = if i == 0 {
                0
            } else {
                rng.gen_range(-drift_max..=drift_max)
            };
        }

        // Grundzeitplaene
        let contact_on = gen_duty(&mut rng, drain_end, 2 * HOUR, 10 * HOUR, 1 * HOUR, 8 * HOUR);
        let mut all_on: Vec<Vec<(Time, Time)>> = Vec::new();
        for i in 0..n_dev {
            let (onmin, onmax, offmin, offmax) = match cfg.profile {
                Profile::Concurrent | Profile::Mixed => (6 * HOUR, 20 * HOUR, 20 * MIN, 3 * HOUR),
                _ => (2 * HOUR, 12 * HOUR, 30 * MIN, 6 * HOUR),
            };
            let mut on = gen_duty(&mut rng, drain_end, onmin, onmax, offmin, offmax);
            // Ein Geraet wochenlang offline
            if matches!(cfg.profile, Profile::LongOffline | Profile::Mixed) && i == n_dev - 1 {
                let len = rng.gen_range(7 * DAY..=13 * DAY);
                let start = rng.gen_range(0..=(horizon.saturating_sub(len)));
                on = punch_hole(on, start, start.saturating_add(len));
            }
            all_on.push(on);
        }

        // Sync-Fenster (§10) fuer Kontakt und jedes Geraet
        let mut contact_windows: Vec<(Time, Time)> = Vec::new();
        let slots = drain_end / SYNC_INTERVAL;
        for slot in 0..slots {
            let center = window_center(&sync_key, slot);
            contact_windows.push((
                center.saturating_sub(SYNC_WINDOW / 2),
                center.saturating_add(SYNC_WINDOW / 2),
            ));
        }
        let mut contact_all = contact_on;
        contact_all.extend(contact_windows.iter().copied());
        sched[0] = Schedule::normalize(contact_all);

        for i in 0..n_dev {
            let mut v = all_on.get(i).cloned().unwrap_or_default();
            let drift = drifts.get(i).copied().unwrap_or(0);
            for slot in 0..slots {
                // Das Geraet rechnet mit seiner lokalen Uhr -> Fenster
                // verschiebt sich um den Drift gegenueber dem Kontakt.
                let center = window_center(&sync_key, slot);
                let c = (center as i64).saturating_sub(drift).max(0) as Time;
                let a = c.saturating_sub(SYNC_WINDOW / 2);
                let b = c.saturating_add(SYNC_WINDOW / 2);
                // Bei Langzeit-Offline gilt das Fenster nicht.
                v.push((a, b));
            }
            if matches!(cfg.profile, Profile::LongOffline | Profile::Mixed) && i == n_dev - 1 {
                // Loch erneut stanzen, damit Sync-Fenster es nicht auffuellen.
                let base = all_on.get(i).cloned().unwrap_or_default();
                let holes = hole_of(&base, horizon);
                for (hs, he) in holes {
                    v = punch_hole(v, hs, he);
                }
            }
            sched[i + 1] = Schedule::normalize(v);
        }

        // Drain-Phase: alle online
        for s in sched.iter_mut() {
            let mut v = s.on.clone();
            v.push((horizon, drain_end));
            *s = Schedule::normalize(v);
        }

        // --- Ratchets -----------------------------------------------------
        let bob_kp = crypto::KeyPair::from_bytes(crypto::h(&[&session_seed, b"bob-spk"]));
        let bob_pub = {
            use crate::vendor_dr::KeyPair as _;
            bob_kp.public().clone()
        };

        let n_sessions = if cfg.variant == Variant::A2 { n_dev } else { 1 };
        let mut c_dr = Vec::with_capacity(n_sessions);
        let mut c_rng = Vec::with_capacity(n_sessions);
        let mut d_ratchets: Vec<Ratchet> = Vec::with_capacity(n_sessions);
        for s in 0..n_sessions {
            let sk = crypto::sym_from(crypto::h(&[&session_seed, b"pqxdh-sk", &[s as u8]]));
            let mut r = DerivedKeyRng::new(crypto::h(&[&contact_seed, &[s as u8]]));
            r.prime(None);
            let alice = Ratchet::new_alice(&sk, bob_pub.clone(), None, &mut r);
            c_dr.push(alice);
            c_rng.push(r);
            let sk2 = crypto::sym_from(crypto::h(&[&session_seed, b"pqxdh-sk", &[s as u8]]));
            d_ratchets.push(Ratchet::new_bob(sk2, bob_kp.clone(), None));
        }

        let mut devs = Vec::with_capacity(n_dev);
        for i in 0..n_dev {
            let dr = match cfg.variant {
                Variant::A | Variant::AReconcile => d_ratchets.first().cloned(),
                Variant::B => {
                    if i == 0 {
                        d_ratchets.first().cloned()
                    } else {
                        None
                    }
                }
                Variant::A2 => d_ratchets.get(i).cloned(),
            };
            let seed = match cfg.variant {
                // Variante A: alle eigenen Geraete leiten denselben
                // Ratchet-Schluessel ab (guenstigste Annahme, siehe crypto.rs).
                Variant::A | Variant::AReconcile => device_seed,
                _ => crypto::h(&[&device_seed, &[i as u8]]),
            };
            devs.push(MyDevice {
                id: i,
                dr,
                rng: DerivedKeyRng::new(seed),
                history: HashMap::new(),
                seen_env: HashMap::new(),
                pending_sync: vec![Vec::new(); n_dev],
                pending_fwd: Vec::new(),
                pending_to_contact: Vec::new(),
                max_skipped: 0,
                drift: drifts.get(i).copied().unwrap_or(0),
            });
        }

        let p_flap = match cfg.profile {
            Profile::Concurrent | Profile::Mixed => 0.35,
            _ => 0.10,
        };
        let p_sync_drop = match cfg.profile {
            Profile::PartitionMidRatchet | Profile::Mixed => 0.30,
            _ => 0.02,
        };

        Sim {
            cfg,
            rng,
            now: 0,
            seq: 0,
            q: BinaryHeap::new(),
            sched,
            contact: Contact {
                dr: c_dr,
                rng: c_rng,
                queue: Vec::new(),
                pending: Vec::new(),
                by_lid: HashMap::new(),
                in_flight: 0,
                max_skipped: 0,
                ack_decrypt_fail: 0,
            },
            devs,
            n_dev,
            horizon,
            drain_end,
            p_flap,
            p_sync_drop,
            probes: Vec::new(),
            compose_at: HashMap::new(),
            delivered_at: Vec::new(),
            r: RunResult {
                seed: cfg.seed,
                variant: cfg.variant.name(),
                profile: cfg.profile.name(),
                n_devices: n_dev,
                latency_mult: cfg.latency_mult,
                n_msgs: cfg.n_msgs,
                lost: 0,
                unconverged: 0,
                dup_suppressed: 0,
                dup_missed_by_msgid: 0,
                max_skipped_device: 0,
                max_skipped_contact: 0,
                probes: 0,
                probes_converged: 0,
                probes_over_60s: 0,
                conv_max_ms: 0,
                conv_sum_ms: 0,
                ack_dropped: 0,
                send_divergence: 0,
                decrypt_fail_new: 0,
                skip_too_large: 0,
                storage_full: 0,
                attempts: 0,
                delivered: 0,
                delivery_p95_ms: 0,
                delivery_max_ms: 0,
                sync_records: 0,
                attempt_cap_hits: 0,
                undelivered_final: 0,
                link_probes: 0,
                link_converged: 0,
                link_over_60s: 0,
                link_conv_max_ms: 0,
                link_conv_sum_ms: 0,
                link_hist: [0; 7],
            },
        }
    }

    fn push(&mut self, t: Time, kind: EvKind) {
        self.seq = self.seq.saturating_add(1);
        let seq = self.seq;
        self.q.push(Ev { t, seq, kind });
    }

    fn online(&self, node: usize, t: Time) -> bool {
        self.sched.get(node).map(|s| s.online(t)).unwrap_or(false)
    }

    fn latency(&mut self) -> Time {
        let base: u64 = 1500u64.saturating_add(self.rng.gen_range(0u64..6000u64));
        base.saturating_mul(self.cfg.latency_mult as u64)
    }

    fn execute(mut self) -> RunResult {
        // Nachrichten des Kontakts: in Buendeln (Gespraechsphasen) ueber die
        // ersten 10 Tage, damit Warteschlangen und Umordnung entstehen
        // (phase0-spikeplan §2: "1000 Nachrichten in zufaelliger Reihenfolge").
        let n_bursts = self.rng.gen_range(8..=40usize);
        let bursts: Vec<(Time, Time)> = (0..n_bursts)
            .map(|_| {
                (
                    self.rng.gen_range(0..(10 * DAY)),
                    self.rng.gen_range(1 * MIN..=60 * MIN),
                )
            })
            .collect();
        let mut times: Vec<Time> = (0..self.cfg.n_msgs)
            .map(|_| {
                let b = self.rng.gen_range(0..n_bursts);
                let (start, len) = bursts.get(b).copied().unwrap_or((0, MIN));
                start.saturating_add(self.rng.gen_range(0..=len))
            })
            .collect();
        times.sort_unstable();
        for (i, t) in times.iter().enumerate() {
            self.push(*t, EvKind::Compose(i as u32));
            self.compose_at.insert(i as u32, *t);
        }

        // Online-Uebergaenge als Ereignisse
        let starts: Vec<(usize, Vec<Time>)> = self
            .sched
            .iter()
            .enumerate()
            .map(|(i, s)| (i, s.starts()))
            .collect();
        for (node, ts) in starts {
            for t in ts {
                self.push(t, EvKind::Online(node));
            }
        }
        self.push(self.horizon, EvKind::DrainStart);
        let mut t = TICK;
        while t < self.drain_end {
            self.push(t, EvKind::Tick);
            t = t.saturating_add(TICK);
        }

        let mut guard: u64 = 0;
        while let Some(ev) = self.q.pop() {
            guard = guard.saturating_add(1);
            if guard > 8_000_000 {
                break;
            }
            if ev.t > self.drain_end {
                break;
            }
            self.now = ev.t;
            match ev.kind {
                EvKind::Compose(idx) => self.on_compose(idx),
                EvKind::Online(node) => self.on_online(node),
                EvKind::Arrive { to, pkt } => self.on_arrive(to, pkt),
                EvKind::AckTimeout { idx, attempt } => self.on_ack_timeout(idx, attempt),
                EvKind::Tick => {
                    self.update_links();
                    for d in 0..self.n_dev {
                        self.flush_device(d);
                    }
                    self.flush_contact();
                }
                EvKind::DrainStart => {
                    self.update_links();
                    for d in 0..self.n_dev {
                        self.flush_device(d);
                    }
                    self.flush_contact();
                }
            }
        }

        self.finish()
    }

    // ---------------------------------------------------------------- Kontakt

    fn on_compose(&mut self, idx: u32) {
        let lid = idx;
        let env = if self.cfg.variant == Variant::A2 {
            // A2: pro Zielgeraet eigene Session -> erst beim Senden
            // verschluesselbar. Klartext bleibt bis dahin in der Outbox.
            None
        } else {
            Some(self.contact_encrypt(0, &pt_content(lid)))
        };
        let env = match env {
            Some(Some(e)) => Some(e),
            Some(None) => None,
            None => None,
        };
        self.contact.queue.push(OutMsg {
            lid,
            env,
            delivered: false,
            attempts: 0,
            in_flight: false,
        });
        self.contact
            .by_lid
            .insert(lid, (self.contact.queue.len() as u32).saturating_sub(1));
        self.contact.pending.push(lid);
        self.flush_contact();
    }

    fn contact_encrypt(&mut self, sess: usize, pt: &[u8]) -> Option<Envelope> {
        let dr = self.contact.dr.get_mut(sess)?;
        let rng = self.contact.rng.get_mut(sess)?;
        let dhr = dr.dhr_public().cloned();
        rng.prime(dhr.as_ref());
        match dr.try_ratchet_encrypt(pt, AD, rng) {
            Ok((header, ct)) => Some(Envelope { header, ct }),
            Err(_) => None,
        }
    }

    /// Deterministische Zielreihenfolge (§9.2) mit transienten
    /// Verbindungsfehlern (`p_flap`).
    fn pick_target(&mut self) -> Option<usize> {
        for d in 0..self.n_dev {
            if self.online(d + 1, self.now) && self.rng.gen_bool(1.0 - self.p_flap) {
                return Some(d);
            }
        }
        None
    }

    fn flush_contact(&mut self) {
        if !self.online(0, self.now) {
            return;
        }
        while self.contact.in_flight < MAX_INFLIGHT && !self.contact.pending.is_empty() {
            let n = self.contact.pending.len();
            let k = self.rng.gen_range(0..n);
            let lid = self.contact.pending.swap_remove(k);
            let qidx = match self.contact.by_lid.get(&lid) {
                Some(v) => *v as usize,
                None => continue,
            };
            let (already, tries) = self
                .contact
                .queue
                .get(qidx)
                .map(|m| (m.delivered, m.attempts))
                .unwrap_or((true, 0));
            if already {
                continue;
            }
            if tries >= self.cfg.max_attempts {
                // Aufgegeben: bleibt dauerhaft WAITING (§9.4), nie DELIVERED.
                self.r.attempt_cap_hits = self.r.attempt_cap_hits.saturating_add(1);
                continue;
            }
            let target = match self.pick_target() {
                Some(t) => t,
                None => {
                    // Kein Geraet erreichbar -> WAITING (§9.4)
                    self.contact.pending.push(lid);
                    return;
                }
            };
            let sess = if self.cfg.variant == Variant::A2 { target } else { 0 };
            let env = {
                let existing = self
                    .contact
                    .queue
                    .get(qidx)
                    .and_then(|m| m.env.clone());
                match existing {
                    Some(e) => Some(e),
                    None => self.contact_encrypt(sess, &pt_content(lid)),
                }
            };
            let env = match env {
                Some(e) => e,
                None => {
                    self.contact.pending.push(lid);
                    return;
                }
            };
            if self.cfg.variant != Variant::A2 {
                if let Some(m) = self.contact.queue.get_mut(qidx) {
                    m.env = Some(env.clone());
                }
            }
            let attempt = {
                let m = match self.contact.queue.get_mut(qidx) {
                    Some(m) => m,
                    None => continue,
                };
                m.attempts = m.attempts.saturating_add(1);
                m.in_flight = true;
                m.attempts
            };
            self.contact.in_flight = self.contact.in_flight.saturating_add(1);
            self.r.attempts = self.r.attempts.saturating_add(1);
            let lat = self.latency();
            let t = self.now.saturating_add(lat);
            self.push(
                t,
                EvKind::Arrive {
                    to: target + 1,
                    pkt: Pkt::ToMe {
                        env,
                        idx: lid,
                        attempt,
                    },
                },
            );
            self.push(
                self.now.saturating_add(ACK_TIMEOUT),
                EvKind::AckTimeout { idx: lid, attempt },
            );
        }
    }

    fn on_ack_timeout(&mut self, idx: u32, attempt: u32) {
        let qidx = match self.contact.by_lid.get(&idx) {
            Some(v) => *v as usize,
            None => return,
        };
        let retry = match self.contact.queue.get_mut(qidx) {
            Some(m) => {
                if m.delivered || m.attempts != attempt || !m.in_flight {
                    false
                } else {
                    m.in_flight = false;
                    true
                }
            }
            None => false,
        };
        if retry {
            self.contact.in_flight = self.contact.in_flight.saturating_sub(1);
            self.contact.pending.push(idx);
            self.flush_contact();
        }
    }

    // ---------------------------------------------------------------- Empfang

    fn on_online(&mut self, node: usize) {
        if node == 0 {
            self.flush_contact();
            return;
        }
        let d = node.saturating_sub(1);
        // Konvergenzsonde nur bei echter Wiederverbindung (>= 1 h offline).
        let gap = self
            .sched
            .get(node)
            .map(|s| s.gap_before(self.now))
            .unwrap_or(0);
        if gap >= HOUR {
            self.open_probe(d);
        }
        // Beide Richtungen anstossen: das wiederverbundene Geraet und die
        // Geschwister, die Daten fuer es halten.
        for x in 0..self.n_dev {
            self.flush_device(x);
        }
        self.flush_contact();
    }

    /// `update_links` bleibt als No-op-Haken erhalten; `t_link` wird beim
    /// Anlegen der Sonde exakt aus den Zeitplaenen berechnet.
    fn update_links(&mut self) {}

    /// Erster Zeitpunkt >= `from`, zu dem die Knoten `a` und `b` gleichzeitig
    /// online sind.
    fn first_overlap(&self, a: usize, b: usize, from: Time) -> Option<Time> {
        let sa = self.sched.get(a)?;
        let sb = self.sched.get(b)?;
        let mut i = 0usize;
        let mut j = 0usize;
        while let (Some((a0, a1)), Some((b0, b1))) = (sa.on.get(i), sb.on.get(j)) {
            let lo = (*a0).max(*b0).max(from);
            let hi = (*a1).min(*b1);
            if lo < hi {
                return Some(lo);
            }
            if a1 <= b1 {
                i = i.saturating_add(1);
            } else {
                j = j.saturating_add(1);
            }
        }
        None
    }

    fn open_probe(&mut self, d: usize) {
        let mine: HashSet<u32> = self
            .devs
            .get(d)
            .map(|x| x.history.keys().copied().collect())
            .unwrap_or_default();
        let remaining: HashSet<u32> = self
            .devs
            .iter()
            .filter(|x| x.id != d)
            .flat_map(|x| x.history.keys().copied())
            .filter(|k| !mine.contains(k))
            .collect();
        if remaining.is_empty() {
            return;
        }
        // Erster Zeitpunkt, zu dem d und ein Geschwistergeraet, das die
        // fehlenden Daten tatsaechlich haelt, gleichzeitig online sind.
        let mut t_link: Option<Time> = None;
        for s in 0..self.n_dev {
            if s == d {
                continue;
            }
            let holds = self
                .devs
                .get(s)
                .map(|x| remaining.iter().any(|k| x.history.contains_key(k)))
                .unwrap_or(false);
            if !holds {
                continue;
            }
            if let Some(t) = self.first_overlap(d + 1, s + 1, self.now) {
                t_link = Some(match t_link {
                    Some(cur) => cur.min(t),
                    None => t,
                });
            }
        }
        self.probes.push(Probe {
            dev: d,
            t0: self.now,
            remaining,
            done: None,
            t_link,
        });
    }

    fn flush_device(&mut self, d: usize) {
        if !self.online(d + 1, self.now) {
            return;
        }
        // Geschwister-SyncRecords
        for s in 0..self.n_dev {
            if s == d || !self.online(s + 1, self.now) {
                continue;
            }
            let recs: Vec<SyncRecord> = match self.devs.get_mut(d) {
                Some(dev) => match dev.pending_sync.get_mut(s) {
                    Some(v) => std::mem::take(v),
                    None => Vec::new(),
                },
                None => Vec::new(),
            };
            if recs.is_empty() {
                continue;
            }
            let lat = self.latency();
            for (i, rec) in recs.into_iter().enumerate() {
                let t = self
                    .now
                    .saturating_add(lat)
                    .saturating_add((i as u64).saturating_mul(SYNC_REC_MS));
                self.r.sync_records = self.r.sync_records.saturating_add(1);
                self.push(
                    t,
                    EvKind::Arrive {
                        to: s + 1,
                        pkt: Pkt::Sync(rec),
                    },
                );
            }
        }
        // Variante B: Weiterleitung ans Primaergeraet
        if self.cfg.variant == Variant::B && d != 0 && self.online(1, self.now) {
            let fwd: Vec<Envelope> = match self.devs.get_mut(d) {
                Some(dev) => std::mem::take(&mut dev.pending_fwd),
                None => Vec::new(),
            };
            let lat = self.latency();
            for (i, env) in fwd.into_iter().enumerate() {
                let t = self
                    .now
                    .saturating_add(lat)
                    .saturating_add((i as u64).saturating_mul(SYNC_REC_MS));
                self.push(
                    t,
                    EvKind::Arrive {
                        to: 1,
                        pkt: Pkt::Fwd { env, from: d },
                    },
                );
            }
        }
        // Wartende Acks an den Kontakt
        if self.online(0, self.now) {
            let outs: Vec<Envelope> = match self.devs.get_mut(d) {
                Some(dev) => std::mem::take(&mut dev.pending_to_contact),
                None => Vec::new(),
            };
            let lat = self.latency();
            for (i, env) in outs.into_iter().enumerate() {
                let t = self
                    .now
                    .saturating_add(lat)
                    .saturating_add((i as u64).saturating_mul(MSG_SPACING));
                self.push(
                    t,
                    EvKind::Arrive {
                        to: 0,
                        pkt: Pkt::ToContact { env },
                    },
                );
            }
        }
    }

    fn on_arrive(&mut self, to: usize, pkt: Pkt) {
        if !self.online(to, self.now) {
            // Verbindung scheitert. Fuer Nachrichten des Kontakts greift der
            // Ack-Timeout (§9.2). Geschwister-SyncRecords und Weiterleitungen
            // haben keinen Timeout — sie muessen in die Warteschlange zurueck,
            // sonst waere der Verlust ein Artefakt des Modells.
            match pkt {
                Pkt::Sync(rec) => {
                    let from = rec.from;
                    let s = to.saturating_sub(1);
                    if let Some(dev) = self.devs.get_mut(from) {
                        if let Some(v) = dev.pending_sync.get_mut(s) {
                            v.push(rec);
                        }
                    }
                }
                Pkt::Fwd { env, from } => {
                    if let Some(dev) = self.devs.get_mut(from) {
                        dev.pending_fwd.push(env);
                    }
                }
                Pkt::ToContact { env } => {
                    // Ack geht verloren; der Kontakt wiederholt die Nachricht.
                    let _ = env;
                }
                Pkt::ToMe { .. } => {}
            }
            return;
        }
        match pkt {
            Pkt::ToMe { env, idx, attempt } => {
                self.dev_receive(to.saturating_sub(1), env, idx, attempt);
                self.flush_device(to.saturating_sub(1));
            }
            Pkt::ToContact { env } => self.contact_receive(env),
            Pkt::Sync(rec) => {
                self.dev_apply_sync(to.saturating_sub(1), rec);
                self.flush_device(to.saturating_sub(1));
            }
            Pkt::Fwd { env, from: _ } => {
                self.primary_receive_fwd(env);
                self.flush_device(0);
            }
        }
    }

    fn note_history(&mut self, d: usize, lid: u32, from_msgid: Option<[u8; 32]>) {
        let now = self.now;
        let mut inserted = false;
        if let Some(dev) = self.devs.get_mut(d) {
            if dev.history.contains_key(&lid) {
                // Doppelte Zustellung: die Deduplikation faengt sie ab.
                return_dup(&mut self.r, from_msgid, dev, lid);
                return;
            }
            dev.history.insert(lid, now);
            inserted = true;
        }
        if inserted {
            self.check_probes(d, lid);
        }
    }

    fn check_probes(&mut self, d: usize, lid: u32) {
        let now = self.now;
        for p in self.probes.iter_mut() {
            if p.dev == d && p.done.is_none() {
                p.remaining.remove(&lid);
                if p.remaining.is_empty() {
                    p.done = Some(now);
                }
            }
        }
    }

    fn dev_receive(&mut self, d: usize, env: Envelope, lid: u32, _attempt: u32) {
        let mid = env.msg_id();
        let known = self
            .devs
            .get(d)
            .map(|x| x.seen_env.contains_key(&mid))
            .unwrap_or(false);
        if known {
            // Wiederholung: frisches Ack ohne erneute Entschluesselung.
            self.dev_send_ack(d, lid, true);
            return;
        }

        match self.cfg.variant {
            Variant::B if d != 0 => {
                // Zweitgeraet kann nicht entschluesseln -> Store-and-Forward.
                if let Some(dev) = self.devs.get_mut(d) {
                    dev.pending_fwd.push(env);
                }
                self.flush_device(d);
                return;
            }
            _ => {}
        }

        let res = {
            let dev = match self.devs.get_mut(d) {
                Some(x) => x,
                None => return,
            };
            let dr = match dev.dr.as_mut() {
                Some(x) => x,
                None => return,
            };
            let r = dr.ratchet_decrypt(&env.header, &env.ct, AD);
            let sk = dr.skipped_key_count();
            if sk > dev.max_skipped {
                dev.max_skipped = sk;
            }
            r
        };
        match res {
            Ok(pt) => {
                if let Some((0x01, l)) = parse_pt(&pt) {
                    if let Some(dev) = self.devs.get_mut(d) {
                        dev.seen_env.insert(mid, l);
                    }
                    self.note_history(d, l, Some(mid));
                    self.dev_send_ack(d, l, false);
                    // dr_delta an die Geschwister (§9.3)
                    self.replicate(d, SyncOp::Recv { env, lid: l });
                }
            }
            Err(e) => {
                self.count_decrypt_err(d, e, lid);
            }
        }
    }

    fn primary_receive_fwd(&mut self, env: Envelope) {
        let mid = env.msg_id();
        let known = self
            .devs
            .first()
            .map(|x| x.seen_env.contains_key(&mid))
            .unwrap_or(false);
        if known {
            if let Some(lid) = self.devs.first().and_then(|x| x.seen_env.get(&mid).copied()) {
                self.dev_send_ack(0, lid, true);
            }
            return;
        }
        let res = {
            let dev = match self.devs.get_mut(0) {
                Some(x) => x,
                None => return,
            };
            let dr = match dev.dr.as_mut() {
                Some(x) => x,
                None => return,
            };
            let r = dr.ratchet_decrypt(&env.header, &env.ct, AD);
            let sk = dr.skipped_key_count();
            if sk > dev.max_skipped {
                dev.max_skipped = sk;
            }
            r
        };
        match res {
            Ok(pt) => {
                if let Some((0x01, l)) = parse_pt(&pt) {
                    if let Some(dev) = self.devs.get_mut(0) {
                        dev.seen_env.insert(mid, l);
                    }
                    self.note_history(0, l, Some(mid));
                    self.dev_send_ack(0, l, false);
                    self.replicate(0, SyncOp::Plain { lid: l });
                }
            }
            Err(e) => self.count_decrypt_err(0, e, 0),
        }
    }

    fn count_decrypt_err(&mut self, _d: usize, e: DecryptError, _lid: u32) {
        match e {
            DecryptError::SkipTooLarge => {
                self.r.skip_too_large = self.r.skip_too_large.saturating_add(1);
                self.r.decrypt_fail_new = self.r.decrypt_fail_new.saturating_add(1);
            }
            DecryptError::StorageFull => {
                self.r.storage_full = self.r.storage_full.saturating_add(1);
                self.r.decrypt_fail_new = self.r.decrypt_fail_new.saturating_add(1);
            }
            _ => {
                self.r.decrypt_fail_new = self.r.decrypt_fail_new.saturating_add(1);
            }
        }
    }

    fn dev_send_ack(&mut self, d: usize, lid: u32, _reack: bool) {
        let sess_ok = self
            .devs
            .get(d)
            .map(|x| x.dr.is_some())
            .unwrap_or(false);
        if !sess_ok {
            return;
        }
        let pt = pt_ack(lid);
        let env = {
            let dev = match self.devs.get_mut(d) {
                Some(x) => x,
                None => return,
            };
            let dr = match dev.dr.as_mut() {
                Some(x) => x,
                None => return,
            };
            let dhr = dr.dhr_public().cloned();
            dev.rng.prime(dhr.as_ref());
            match dr.try_ratchet_encrypt(&pt, AD, &mut dev.rng) {
                Ok((header, ct)) => Envelope { header, ct },
                Err(_) => return,
            }
        };
        // Sendekette den Geschwistern nachziehen (§9.3)
        if matches!(self.cfg.variant, Variant::A | Variant::AReconcile) {
            self.replicate(
                d,
                SyncOp::Sent {
                    env: env.clone(),
                    lid,
                },
            );
        }
        if self.online(0, self.now) && self.online(d + 1, self.now) {
            let lat = self.latency();
            let t = self.now.saturating_add(lat);
            self.push(
                t,
                EvKind::Arrive {
                    to: 0,
                    pkt: Pkt::ToContact { env },
                },
            );
        } else if let Some(dev) = self.devs.get_mut(d) {
            dev.pending_to_contact.push(env);
        }
    }

    fn replicate(&mut self, from: usize, op: SyncOp) {
        let snapshot = if self.cfg.variant == Variant::AReconcile && from == 0 {
            self.devs
                .get(0)
                .and_then(|x| x.dr.clone())
                .map(Box::new)
        } else {
            None
        };
        let rec = SyncRecord {
            from,
            ops: vec![op],
            snapshot,
        };
        for s in 0..self.n_dev {
            if s == from {
                continue;
            }
            let drop_it = self.rng.gen_bool(self.p_sync_drop);
            let deliverable = self.online(s + 1, self.now) && self.online(from + 1, self.now);
            if deliverable && !drop_it {
                let lat = self.latency();
                let t = self.now.saturating_add(lat);
                self.r.sync_records = self.r.sync_records.saturating_add(1);
                self.push(
                    t,
                    EvKind::Arrive {
                        to: s + 1,
                        pkt: Pkt::Sync(rec.clone()),
                    },
                );
            } else if let Some(dev) = self.devs.get_mut(from) {
                if let Some(v) = dev.pending_sync.get_mut(s) {
                    v.push(rec.clone());
                }
            }
        }
    }

    fn dev_apply_sync(&mut self, d: usize, rec: SyncRecord) {
        let mut diverged = false;
        for op in rec.ops.iter() {
            match op {
                SyncOp::Plain { lid } => {
                    self.note_history(d, *lid, None);
                }
                SyncOp::Recv { env, lid } => {
                    self.note_history(d, *lid, Some(env.msg_id()));
                    let mid = env.msg_id();
                    if let Some(dev) = self.devs.get_mut(d) {
                        dev.seen_env.insert(mid, *lid);
                        if let Some(dr) = dev.dr.as_mut() {
                            let _ = dr.ratchet_decrypt(&env.header, &env.ct, AD);
                            let sk = dr.skipped_key_count();
                            if sk > dev.max_skipped {
                                dev.max_skipped = sk;
                            }
                        }
                    }
                }
                SyncOp::Sent { env, lid } => {
                    let pt = pt_ack(*lid);
                    if let Some(dev) = self.devs.get_mut(d) {
                        if let Some(dr) = dev.dr.as_mut() {
                            let dhr = dr.dhr_public().cloned();
                            dev.rng.prime(dhr.as_ref());
                            match dr.try_ratchet_encrypt(&pt, AD, &mut dev.rng) {
                                Ok((header, ct)) => {
                                    let mine = Envelope { header, ct };
                                    if mine.msg_id() != env.msg_id() {
                                        diverged = true;
                                    }
                                }
                                Err(_) => diverged = true,
                            }
                        }
                    }
                }
            }
        }
        if diverged {
            self.r.send_divergence = self.r.send_divergence.saturating_add(1);
            // Reconciliation (nur Variante A-reconcile): das Geraet mit der
            // hoeheren ID uebernimmt den Zustand des kanonischen Zweigs
            // (Geraet 0), aber niemals unter Rueckschritt der Empfangskette —
            // sonst gehen bereits verbrauchte Message Keys verloren.
            if self.cfg.variant == Variant::AReconcile && rec.from < d {
                let take = match (rec.snapshot.as_ref(), self.devs.get(d).and_then(|x| x.dr.as_ref()))
                {
                    (Some(snap), Some(mine)) => snap.nr() >= mine.nr(),
                    (Some(_), None) => true,
                    _ => false,
                };
                if take {
                    if let (Some(snap), Some(dev)) = (rec.snapshot.clone(), self.devs.get_mut(d)) {
                        dev.dr = Some(*snap);
                    }
                }
            }
        }
    }

    fn contact_receive(&mut self, env: Envelope) {
        let n = self.contact.dr.len();
        let mut ok = None;
        for s in 0..n {
            let res = {
                let dr = match self.contact.dr.get_mut(s) {
                    Some(x) => x,
                    None => continue,
                };
                let r = dr.ratchet_decrypt(&env.header, &env.ct, AD);
                let sk = dr.skipped_key_count();
                if sk > self.contact.max_skipped {
                    self.contact.max_skipped = sk;
                }
                r
            };
            if let Ok(pt) = res {
                ok = Some(pt);
                break;
            }
        }
        let pt = match ok {
            Some(p) => p,
            None => {
                self.contact.ack_decrypt_fail = self.contact.ack_decrypt_fail.saturating_add(1);
                self.r.ack_dropped = self.r.ack_dropped.saturating_add(1);
                return;
            }
        };
        if let Some((0x02, lid)) = parse_pt(&pt) {
            let qidx = match self.contact.by_lid.get(&lid) {
                Some(v) => *v as usize,
                None => return,
            };
            let was = match self.contact.queue.get_mut(qidx) {
                Some(m) => {
                    let w = m.delivered;
                    // DELIVERED ausschliesslich hier — nach echtem E2E-Ack
                    // (§9.4, CLAUDE.md).
                    m.delivered = true;
                    if m.in_flight {
                        m.in_flight = false;
                    }
                    w
                }
                None => true,
            };
            if !was {
                self.contact.in_flight = self.contact.in_flight.saturating_sub(1);
                self.r.delivered = self.r.delivered.saturating_add(1);
                let c = self.compose_at.get(&lid).copied().unwrap_or(0);
                self.delivered_at.push(self.now.saturating_sub(c));
            }
            self.flush_contact();
        }
    }

    // ---------------------------------------------------------------- Abschluss

    fn finish(mut self) -> RunResult {
        let union: HashSet<u32> = self
            .devs
            .iter()
            .flat_map(|d| d.history.keys().copied())
            .collect();
        self.r.lost = self.cfg.n_msgs.saturating_sub(union.len());
        let mut unconv = 0usize;
        for d in self.devs.iter() {
            for lid in union.iter() {
                if !d.history.contains_key(lid) {
                    unconv = unconv.saturating_add(1);
                }
            }
        }
        self.r.unconverged = unconv;
        self.r.max_skipped_device = self.devs.iter().map(|d| d.max_skipped).max().unwrap_or(0);
        self.r.max_skipped_contact = self.contact.max_skipped;

        let mut sum = 0u64;
        let mut lsum = 0u64;
        self.r.probes = self.probes.len();
        for p in self.probes.iter() {
            match p.done {
                Some(t) => {
                    let dt = t.saturating_sub(p.t0);
                    self.r.probes_converged = self.r.probes_converged.saturating_add(1);
                    sum = sum.saturating_add(dt);
                    if dt > self.r.conv_max_ms {
                        self.r.conv_max_ms = dt;
                    }
                    if dt > 60 * SEC {
                        self.r.probes_over_60s = self.r.probes_over_60s.saturating_add(1);
                    }
                    if let Some(tl) = p.t_link {
                        let dl = t.saturating_sub(tl.max(p.t0));
                        self.r.link_probes = self.r.link_probes.saturating_add(1);
                        self.r.link_converged = self.r.link_converged.saturating_add(1);
                        lsum = lsum.saturating_add(dl);
                        if dl > self.r.link_conv_max_ms {
                            self.r.link_conv_max_ms = dl;
                        }
                        if dl > 60 * SEC {
                            self.r.link_over_60s = self.r.link_over_60s.saturating_add(1);
                        }
                        let b = if dl < SEC {
                            0
                        } else if dl < 5 * SEC {
                            1
                        } else if dl < 15 * SEC {
                            2
                        } else if dl < 60 * SEC {
                            3
                        } else if dl < 300 * SEC {
                            4
                        } else if dl < 3600 * SEC {
                            5
                        } else {
                            6
                        };
                        if let Some(c) = self.r.link_hist.get_mut(b) {
                            *c = c.saturating_add(1);
                        }
                    }
                }
                None => {
                    self.r.probes_over_60s = self.r.probes_over_60s.saturating_add(1);
                    if p.t_link.is_some() {
                        self.r.link_probes = self.r.link_probes.saturating_add(1);
                        self.r.link_over_60s = self.r.link_over_60s.saturating_add(1);
                        if let Some(c) = self.r.link_hist.get_mut(6) {
                            *c = c.saturating_add(1);
                        }
                    }
                }
            }
        }
        self.r.conv_sum_ms = sum;
        self.r.link_conv_sum_ms = lsum;
        self.r.undelivered_final = self.contact.queue.iter().filter(|m| !m.delivered).count();

        self.delivered_at.sort_unstable();
        if !self.delivered_at.is_empty() {
            let idx = (self.delivered_at.len() * 95) / 100;
            let idx = idx.min(self.delivered_at.len().saturating_sub(1));
            self.r.delivery_p95_ms = self.delivered_at.get(idx).copied().unwrap_or(0);
            self.r.delivery_max_ms = self.delivered_at.last().copied().unwrap_or(0);
        }
        self.r
    }
}

fn return_dup(r: &mut RunResult, from_msgid: Option<[u8; 32]>, dev: &mut MyDevice, lid: u32) {
    r.dup_suppressed = r.dup_suppressed.saturating_add(1);
    // Haette `msg_id = H(dr_header ‖ ciphertext)` (§8) das Duplikat erkannt?
    // Nur, wenn derselbe Envelope-Hash schon gesehen wurde.
    if let Some(mid) = from_msgid {
        match dev.seen_env.get(&mid) {
            Some(prev) if *prev == lid => {}
            _ => {
                r.dup_missed_by_msgid = r.dup_missed_by_msgid.saturating_add(1);
            }
        }
    } else {
        r.dup_missed_by_msgid = r.dup_missed_by_msgid.saturating_add(1);
    }
}

fn gen_duty(
    rng: &mut ChaCha20Rng,
    end: Time,
    on_min: Time,
    on_max: Time,
    off_min: Time,
    off_max: Time,
) -> Vec<(Time, Time)> {
    let mut v = Vec::new();
    let mut t = 0u64;
    while t < end {
        let on = rng.gen_range(on_min..=on_max);
        let off = rng.gen_range(off_min..=off_max);
        v.push((t, (t.saturating_add(on)).min(end)));
        t = t.saturating_add(on).saturating_add(off);
    }
    v
}

fn punch_hole(v: Vec<(Time, Time)>, hs: Time, he: Time) -> Vec<(Time, Time)> {
    let mut out = Vec::with_capacity(v.len());
    for (a, b) in v {
        if b <= hs || a >= he {
            out.push((a, b));
        } else {
            if a < hs {
                out.push((a, hs));
            }
            if b > he {
                out.push((he, b));
            }
        }
    }
    out
}

fn hole_of(base: &[(Time, Time)], horizon: Time) -> Vec<(Time, Time)> {
    // Luecken im Grundzeitplan, die laenger als 3 Tage sind.
    let mut holes = Vec::new();
    let mut prev_end = 0u64;
    for (a, b) in base.iter() {
        if *a > prev_end && a.saturating_sub(prev_end) > 3 * DAY {
            holes.push((prev_end, *a));
        }
        if *b > prev_end {
            prev_end = *b;
        }
    }
    if horizon > prev_end && horizon.saturating_sub(prev_end) > 3 * DAY {
        holes.push((prev_end, horizon));
    }
    holes
}

/// Sync-Fenster-Mittelpunkt nach protokoll-spec §10.
fn window_center(sync_key: &[u8; 32], slot: u64) -> Time {
    let off_mac = crypto::hmac(sync_key, &slot.to_le_bytes());
    let mut o = [0u8; 8];
    if let Some(s) = off_mac.get(..8) {
        o.copy_from_slice(s);
    }
    let off = u64::from_le_bytes(o) % (SYNC_INTERVAL / SEC);
    let mut jbuf = Vec::with_capacity(9);
    jbuf.extend_from_slice(&slot.to_le_bytes());
    jbuf.push(0x01);
    let j_mac = crypto::hmac(sync_key, &jbuf);
    let mut j = [0u8; 8];
    if let Some(s) = j_mac.get(..8) {
        j.copy_from_slice(s);
    }
    let jitter = u64::from_le_bytes(j) % 60;
    slot.saturating_mul(SYNC_INTERVAL)
        .saturating_add(off.saturating_mul(SEC))
        .saturating_add(jitter.saturating_mul(SEC))
}
