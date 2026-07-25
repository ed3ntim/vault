//! CryptoProvider fuer den vendorten Double Ratchet.
//!
//! Primitive **echt** und exakt nach `spec/protokoll-spec.md` §1:
//!   X25519  -> `x25519-dalek` 2.x
//!   HKDF    -> HKDF-SHA-256 (`hkdf` + `sha2`) fuer `KDF_RK`
//!   HMAC    -> HMAC-SHA-256 (`hmac`) fuer `KDF_CK`
//!   AEAD    -> XChaCha20-Poly1305 (`chacha20poly1305`)
//!   H(x)    -> BLAKE3-256 (`blake3`)
//!
//! Es wird **kein** eigenes Primitiv gebaut; nur die von der Ratchet-Bibliothek
//! geforderte Verdrahtung (ADR-05).

use blake3::Hasher as Blake3;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use std::convert::TryInto;
use std::hash::{Hash, Hasher};
use zeroize::Zeroize;

use crate::vendor_dr::{self as dr, DecryptError, KeyPair as KeyPairTrait};

/// Der konkrete Ratchet-Typ dieser Simulation.
pub type Ratchet = dr::DoubleRatchet<VaultCryptoProvider>;

/// 32-Byte-Symmetrieschluessel (Root-, Chain-, Message-Key).
#[derive(Clone, Default)]
pub struct SymKey(pub [u8; 32]);

impl Drop for SymKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SymKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Kein Schluesselmaterial in Ausgaben (CLAUDE.md).
        write!(f, "SymKey(<redacted>)")
    }
}

/// Oeffentlicher X25519-Schluessel.
#[derive(Clone, Debug)]
pub struct PublicKey(pub x25519_dalek::PublicKey);

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes() == other.0.as_bytes()
    }
}
impl Eq for PublicKey {}
impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.as_bytes().hash(state);
    }
}
impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// X25519-Schluesselpaar.
#[derive(Clone)]
pub struct KeyPair {
    secret: x25519_dalek::StaticSecret,
    public: PublicKey,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyPair(<redacted>, {:?})", self.public)
    }
}

impl KeyPairTrait for KeyPair {
    type PublicKey = PublicKey;

    fn new<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        Self::from_bytes(b)
    }

    fn public(&self) -> &PublicKey {
        &self.public
    }
}

impl KeyPair {
    /// Deterministische Konstruktion aus 32 Bytes Schluesselmaterial.
    pub fn from_bytes(b: [u8; 32]) -> Self {
        let secret = x25519_dalek::StaticSecret::from(b);
        let public = PublicKey(x25519_dalek::PublicKey::from(&secret));
        Self { secret, public }
    }
}

/// Verdrahtung der Primitive fuer den vendorten Ratchet.
#[derive(Debug)]
pub struct VaultCryptoProvider;

impl dr::CryptoProvider for VaultCryptoProvider {
    type PublicKey = PublicKey;
    type KeyPair = KeyPair;
    type SharedSecret = x25519_dalek::SharedSecret;
    type RootKey = SymKey;
    type ChainKey = SymKey;
    type MessageKey = SymKey;

    fn diffie_hellman(us: &KeyPair, them: &PublicKey) -> x25519_dalek::SharedSecret {
        us.secret.diffie_hellman(&them.0)
    }

    fn kdf_rk(rk: &SymKey, s: &x25519_dalek::SharedSecret) -> (SymKey, SymKey) {
        let hk = Hkdf::<Sha256>::new(Some(&rk.0), s.as_bytes());
        let mut okm = [0u8; 64];
        // expand kann nur bei zu grosser Ausgabelaenge fehlschlagen; 64 < 255*32.
        if hk.expand(b"vault-s2-ratchet-root", &mut okm).is_err() {
            // Nicht erreichbar; defensiv statt panic.
            okm = [0u8; 64];
        }
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a.copy_from_slice(&okm[..32]);
        b.copy_from_slice(&okm[32..]);
        okm.zeroize();
        (SymKey(a), SymKey(b))
    }

    fn kdf_ck(ck: &SymKey) -> (SymKey, SymKey) {
        // HMAC-SHA-256 mit konstanten Domain-Bytes (Signal-Empfehlung).
        let mk = hmac_sha256(&ck.0, &[0x01]);
        let next = hmac_sha256(&ck.0, &[0x02]);
        (SymKey(next), SymKey(mk))
    }

    fn encrypt(key: &SymKey, pt: &[u8], ad: &[u8]) -> Vec<u8> {
        let (ek, nonce) = derive_aead_params(&key.0);
        let cipher = match XChaCha20Poly1305::new_from_slice(&ek) {
            Ok(c) => c,
            // Laenge ist konstant 32; nicht erreichbar.
            Err(_) => return Vec::new(),
        };
        cipher
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: pt, aad: ad })
            .unwrap_or_default()
    }

    fn decrypt(key: &SymKey, ct: &[u8], ad: &[u8]) -> Result<Vec<u8>, DecryptError> {
        let (ek, nonce) = derive_aead_params(&key.0);
        let cipher =
            XChaCha20Poly1305::new_from_slice(&ek).map_err(|_| DecryptError::DecryptFailure)?;
        cipher
            .decrypt(XNonce::from_slice(&nonce), Payload { msg: ct, aad: ad })
            .map_err(|_| DecryptError::DecryptFailure)
    }
}

fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut mac = match <Hmac<Sha256> as Mac>::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return [0u8; 32],
    };
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// Ableitung von AEAD-Schluessel und 24-Byte-Nonce aus dem Message Key.
/// Deterministisch, aber pro Message Key einzigartig (Message Keys sind
/// einmalig) — entspricht dem Signal-Vorgehen.
fn derive_aead_params(mk: &[u8; 32]) -> ([u8; 32], [u8; 24]) {
    let hk = Hkdf::<Sha256>::new(None, mk);
    let mut okm = [0u8; 56];
    if hk.expand(b"vault-s2-message-keys", &mut okm).is_err() {
        okm = [0u8; 56];
    }
    let mut ek = [0u8; 32];
    let mut nonce = [0u8; 24];
    ek.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..]);
    okm.zeroize();
    (ek, nonce)
}

/// `H(x)` nach `spec/protokoll-spec.md` §1: BLAKE3-256.
pub fn h(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake3::new();
    for p in parts {
        hasher.update(&(p.len() as u64).to_le_bytes());
        hasher.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(hasher.finalize().as_bytes());
    out
}

/// HMAC-SHA-256, oeffentlich fuer die Sync-Fenster-Ableitung (§10).
pub fn hmac(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    hmac_sha256(key, data)
}

/// Deterministischer Schluesselstrom fuer DH-Ratchet-Schluessel.
///
/// **Modellierungsentscheidung (im Bericht ausdruecklich gekennzeichnet):**
/// Variante A verlangt, dass mehrere eigene Geraete dieselbe Kontakt-Session
/// fortfuehren. Der neue DH-Ratchet-Schluessel entsteht in einer echten
/// Implementierung aus frischer Entropie und muesste als Teil von `dr_delta`
/// (`SyncRecord`, §9.3) **im Klartext an alle Geschwister repliziert** werden.
/// Statt diesen Transport nachzubauen, leitet die Simulation den neuen
/// Ratchet-Schluessel kanonisch aus `H(Sitzungs-Seed ‖ dhr_pub)` ab. Jedes
/// Geraet, das denselben Ratchet-Schluessel der Gegenseite gesehen hat,
/// erzeugt damit denselben eigenen Ratchet-Schluessel.
///
/// Das ist die **guenstigste moegliche Annahme fuer Variante A**: die
/// Replikation privater Ratchet-Schluessel ist damit verlustfrei und
/// verzoegerungsfrei. Alle Fehler, die Variante A trotzdem zeigt, sind also
/// nicht auf verlorene `dr_delta` zurueckzufuehren.
pub struct DerivedKeyRng {
    seed: [u8; 32],
    buf: [u8; 32],
    counter: u64,
    used: bool,
}

impl DerivedKeyRng {
    /// Neuer Strom fuer einen Sitzungs-Seed.
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            buf: [0u8; 32],
            counter: 0,
            used: true,
        }
    }

    /// Setzt den Strom auf den kanonischen Schluessel fuer den naechsten
    /// DH-Ratchet-Schritt. `dhr` ist der zuletzt gesehene oeffentliche
    /// Ratchet-Schluessel der Gegenseite.
    pub fn prime(&mut self, dhr: Option<&PublicKey>) {
        let d = dhr.map(|p| pk_bytes(p)).unwrap_or([0u8; 32]);
        self.buf = h(&[&self.seed, b"ratchet-key", &d]);
        self.counter = 0;
        self.used = false;
    }

    fn refill(&mut self) {
        self.buf = h(&[&self.buf, b"more", &self.counter.to_le_bytes()]);
        self.counter = self.counter.wrapping_add(1);
        self.used = false;
    }
}

impl RngCore for DerivedKeyRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut off = 0usize;
        while off < dest.len() {
            if self.used {
                self.refill();
            }
            let take = std::cmp::min(32, dest.len().saturating_sub(off));
            let end = off.saturating_add(take);
            if let (Some(d), Some(s)) = (dest.get_mut(off..end), self.buf.get(..take)) {
                d.copy_from_slice(s);
            }
            self.used = true;
            off = end;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for DerivedKeyRng {}

/// 32 Bytes aus einem Hash in einen `SymKey`.
pub fn sym_from(bytes: [u8; 32]) -> SymKey {
    SymKey(bytes)
}

/// Kopie der 32 Bytes eines PublicKey.
pub fn pk_bytes(pk: &PublicKey) -> [u8; 32] {
    let mut b = [0u8; 32];
    b.copy_from_slice(pk.0.as_bytes());
    b
}

/// Hilfsfunktion: 32-Byte-Array aus Slice (nur intern, laengengeprueft).
pub fn arr32(s: &[u8]) -> [u8; 32] {
    s.try_into().unwrap_or([0u8; 32])
}
