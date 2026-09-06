#![no_std]
//! RFC 8032 Ed25519, Ed25519ctx and Ed25519ph.
//!
//! Secret keys are 32-byte seeds. Signing derives the public key from the seed,
//! avoiding mismatched seed/public-key nonce reuse. Signing uses fixed-schedule
//! scalar and point arithmetic. Verification is variable time. Default verify
//! matches BC: canonical encodings, rejection of small-order public keys and
//! cofactored verification. Explicit strict variants require prime subgroups.
use tc_digest::Digest;
pub use tc_edwards::ContextTooLong;
use tc_edwards::{EdwardsPoint, Fe, Scalar};
use tc_sha::Sha512Digest;

pub const SECRET_KEY_SIZE: usize = 32;
pub const PUBLIC_KEY_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;
pub const PREHASH_SIZE: usize = 64;

/// Generates a seed using caller-provided cryptographic randomness. Seeds are
/// not clamped; pruning occurs only after SHA-512 expansion during signing.
pub fn generate_private_key<R: rand_core::CryptoRng + ?Sized>(rng: &mut R) -> [u8; 32] {
    let mut seed = [0; 32];
    rng.fill_bytes(&mut seed);
    seed
}
const ORDER: [u32; 8] = [
    0x5cf5d3ed, 0x5812631a, 0xa2f79cd6, 0x14def9de, 0, 0, 0, 0x10000000,
];
type Point = EdwardsPoint<Fe>;
type S = Scalar<8>;

fn hash(parts: &[&[u8]]) -> [u8; 64] {
    let mut digest = Sha512Digest::new();
    for part in parts {
        digest.update(part);
    }
    let mut output = [0; 64];
    digest.do_final(&mut output);
    output
}
fn expanded(seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let h = hash(&[seed]);
    let mut scalar: [u8; 32] = h[..32].try_into().unwrap();
    scalar[0] &= 248;
    scalar[31] &= 63;
    scalar[31] |= 64;
    (scalar, h[32..].try_into().unwrap())
}
fn base(scalar: &[u8; 32]) -> Point {
    let (x, y, z, t) = tc_rfc7748::ed25519_base::scalar_mult_base(scalar);
    Point::from_extended(x, y, z, t)
}
fn encode(point: &Point) -> [u8; 32] {
    let mut out = [0; 32];
    point.encode(&mut out);
    out
}
fn scalar_bytes(s: &S) -> [u8; 32] {
    let mut out = [0; 32];
    s.encode(&mut out);
    out
}
fn domain(context: Option<&[u8]>, ph: bool) -> Result<([u8; 289], usize), ContextTooLong> {
    let mut bytes = [0; 289];
    let Some(context) = context else {
        return Ok((bytes, 0));
    };
    if context.len() > 255 {
        return Err(ContextTooLong);
    }
    bytes[..32].copy_from_slice(b"SigEd25519 no Ed25519 collisions");
    bytes[32] = ph as u8;
    bytes[33] = context.len() as u8;
    bytes[34..34 + context.len()].copy_from_slice(context);
    Ok((bytes, 34 + context.len()))
}

/// Derives a public key from a 32-byte seed.
pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    encode(&base(&expanded(seed).0))
}
/// SHA-512 prehash for Ed25519ph. This is not pure Ed25519 on the hash bytes.
pub fn prehash(message: &[u8]) -> [u8; 64] {
    hash(&[message])
}
/// Signs with pure Ed25519 (no context domain).
///
/// ```
/// let seed = [7_u8; 32]; // Use generate_private_key with a CryptoRng for new keys.
/// let public_key = tc_ed25519::public_key(&seed);
/// let signature = tc_ed25519::sign(&seed, b"message");
/// assert!(tc_ed25519::verify(&public_key, b"message", &signature));
/// ```
pub fn sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    sign_inner(seed, message, None, false).unwrap()
}
/// Signs with Ed25519ctx. An empty context remains distinct from pure Ed25519.
pub fn sign_ctx(
    seed: &[u8; 32],
    message: &[u8],
    context: &[u8],
) -> Result<[u8; 64], ContextTooLong> {
    sign_inner(seed, message, Some(context), false)
}
/// Signs a SHA-512 prehash with Ed25519ph domain separation.
pub fn sign_prehashed(
    seed: &[u8; 32],
    prehash: &[u8; 64],
    context: &[u8],
) -> Result<[u8; 64], ContextTooLong> {
    sign_inner(seed, prehash, Some(context), true)
}
fn sign_inner(
    seed: &[u8; 32],
    message: &[u8],
    context: Option<&[u8]>,
    ph: bool,
) -> Result<[u8; 64], ContextTooLong> {
    let (dom, len) = domain(context, ph)?;
    let dom = &dom[..len];
    let (a, prefix) = expanded(seed);
    let pk = encode(&base(&a));
    let r = S::reduce(&hash(&[dom, &prefix, message]), &ORDER);
    let encoded_r = encode(&base(&scalar_bytes(&r)));
    let k = S::reduce(&hash(&[dom, &encoded_r, &pk, message]), &ORDER);
    let s = k.mul_add(&S::reduce(&a, &ORDER), &r, &ORDER);
    let mut signature = [0; 64];
    signature[..32].copy_from_slice(&encoded_r);
    s.encode(&mut signature[32..]);
    Ok(signature)
}
/// BC-compatible pure Ed25519 verification with cofactor clearing.
pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    verify_inner(public_key, message, signature, None, false, false)
}
/// BC-compatible Ed25519ctx verification; oversized contexts fail.
pub fn verify_ctx(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
    context: &[u8],
) -> bool {
    verify_inner(public_key, message, signature, Some(context), false, false)
}
/// BC-compatible Ed25519ph verification of a SHA-512 prehash.
pub fn verify_prehashed(
    public_key: &[u8; 32],
    prehash: &[u8; 64],
    signature: &[u8; 64],
    context: &[u8],
) -> bool {
    verify_inner(public_key, prehash, signature, Some(context), true, false)
}
/// Checks canonical encoding, nonidentity and prime-subgroup membership.
pub fn validate_public_key(public_key: &[u8; 32]) -> bool {
    Point::decode(public_key)
        .is_some_and(|p| !p.is_identity() && p.multiply(&order_bytes()).is_identity())
}

/// Checks canonical encoding and rejects small-order public keys, matching BC's partial validation.
pub fn validate_public_key_partial(public_key: &[u8; 32]) -> bool {
    Point::decode(public_key).is_some_and(|p| !p.multiply(&[8]).is_identity())
}
/// Pure Ed25519 verification requiring nonidentity A and prime-subgroup A/R.
pub fn verify_strict(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    verify_inner(public_key, message, signature, None, false, true)
}
/// Ed25519ctx verification requiring prime-subgroup A/R.
pub fn verify_ctx_strict(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
    context: &[u8],
) -> bool {
    verify_inner(public_key, message, signature, Some(context), false, true)
}
/// Ed25519ph verification requiring prime-subgroup A/R.
pub fn verify_prehashed_strict(
    public_key: &[u8; 32],
    prehash: &[u8; 64],
    signature: &[u8; 64],
    context: &[u8],
) -> bool {
    verify_inner(public_key, prehash, signature, Some(context), true, true)
}
fn order_bytes() -> [u8; 32] {
    let mut out = [0; 32];
    for (i, w) in ORDER.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}
fn verify_inner(
    pk: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
    context: Option<&[u8]>,
    ph: bool,
    strict: bool,
) -> bool {
    let Ok((dom, len)) = domain(context, ph) else {
        return false;
    };
    if !S::is_canonical(&signature[32..], &ORDER) {
        return false;
    }
    let Some(a) = Point::decode(pk) else {
        return false;
    };
    let Some(r) = Point::decode(&signature[..32]) else {
        return false;
    };
    if strict {
        if a.is_identity()
            || !a.multiply(&order_bytes()).is_identity()
            || !r.multiply(&order_bytes()).is_identity()
        {
            return false;
        }
    } else if a.multiply(&[8]).is_identity() {
        return false;
    }
    let k = S::reduce(&hash(&[&dom[..len], &signature[..32], pk, message]), &ORDER);
    let s: &[u8; 32] = signature[32..].try_into().unwrap();
    let mut left = base(s);
    let mut right = r.add(&a.multiply(&scalar_bytes(&k)));
    if !strict {
        for _ in 0..3 {
            left = left.add(&left);
            right = right.add(&right);
        }
    }
    left.equals(&right)
}
