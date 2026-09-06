#![no_std]
//! RFC 8032 Ed448 and Ed448ph signatures, including context domain separation.
//!
//! Keys are 57-byte seeds. Signing derives the public key from the seed and
//! uses fixed-schedule scalar and point arithmetic. Verification is variable
//! time. Default verification matches BC's canonical encodings, rejection of
//! small-order public keys and cofactor clearing. Strict variants are explicit.
use tc_digest::{Digest, Xof};
pub use tc_edwards::ContextTooLong;
use tc_edwards::{EdwardsPoint, Fe448, Scalar};
use tc_keccak::ShakeDigest;
pub const SECRET_KEY_SIZE: usize = 57;
pub const PUBLIC_KEY_SIZE: usize = 57;
pub const SIGNATURE_SIZE: usize = 114;
pub const PREHASH_SIZE: usize = 64;

/// Generates a seed from caller-provided cryptographic randomness. The seed
/// itself is not pruned; pruning applies to its SHAKE256 expansion.
pub fn generate_private_key<R: rand_core::CryptoRng + ?Sized>(rng: &mut R) -> [u8; 57] {
    let mut seed = [0; 57];
    rng.fill_bytes(&mut seed);
    seed
}
const ORDER: [u32; 14] = [
    0xab5844f3, 0x2378c292, 0x8dc58f55, 0x216cc272, 0xaed63690, 0xc44edb49, 0x7cca23e9, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x3fffffff,
];
include!("base.rs");
type Point = EdwardsPoint<Fe448>;
type S = Scalar<14>;

fn hash<const N: usize>(parts: &[&[u8]]) -> [u8; N] {
    let mut digest = ShakeDigest::new(256);
    for part in parts {
        digest.update(part);
    }
    let mut output = [0; N];
    digest.output_final(&mut output);
    output
}
fn expanded(seed: &[u8; 57]) -> ([u8; 57], [u8; 57]) {
    let h = hash::<114>(&[seed]);
    let mut scalar: [u8; 57] = h[..57].try_into().unwrap();
    scalar[0] &= 252;
    scalar[55] |= 128;
    scalar[56] = 0;
    (scalar, h[57..].try_into().unwrap())
}
fn base(scalar: &[u8; 57]) -> Point {
    Point::decode(&BASE)
        .expect("Ed448 generator")
        .multiply(scalar)
}
fn encode(point: &Point) -> [u8; 57] {
    let mut out = [0; 57];
    point.encode(&mut out);
    out
}
fn scalar_bytes(s: &S) -> [u8; 57] {
    let mut out = [0; 57];
    s.encode(&mut out);
    out
}
fn domain(context: &[u8], ph: bool) -> Result<([u8; 265], usize), ContextTooLong> {
    if context.len() > 255 {
        return Err(ContextTooLong);
    }
    let mut bytes = [0; 265];
    bytes[..8].copy_from_slice(b"SigEd448");
    bytes[8] = ph as u8;
    bytes[9] = context.len() as u8;
    bytes[10..10 + context.len()].copy_from_slice(context);
    Ok((bytes, 10 + context.len()))
}
/// Derives the canonical public key from a seed.
pub fn public_key(seed: &[u8; 57]) -> [u8; 57] {
    encode(&base(&expanded(seed).0))
}
/// Produces the 64-byte SHAKE256 prehash required by Ed448ph.
pub fn prehash(message: &[u8]) -> [u8; 64] {
    hash(&[message])
}
/// Signs with Ed448. Use an empty context when the protocol specifies none.
///
/// ```
/// let seed = [7_u8; 57]; // Use generate_private_key with a CryptoRng for new keys.
/// let public_key = tc_ed448::public_key(&seed);
/// let signature = tc_ed448::sign(&seed, b"message", b"protocol").unwrap();
/// assert!(tc_ed448::verify(&public_key, b"message", &signature, b"protocol"));
/// ```
pub fn sign(seed: &[u8; 57], message: &[u8], context: &[u8]) -> Result<[u8; 114], ContextTooLong> {
    sign_inner(seed, message, context, false)
}
/// Signs a 64-byte SHAKE256 prehash with the Ed448ph domain.
pub fn sign_prehashed(
    seed: &[u8; 57],
    prehash: &[u8; 64],
    context: &[u8],
) -> Result<[u8; 114], ContextTooLong> {
    sign_inner(seed, prehash, context, true)
}
fn sign_inner(
    seed: &[u8; 57],
    message: &[u8],
    context: &[u8],
    ph: bool,
) -> Result<[u8; 114], ContextTooLong> {
    let (dom, len) = domain(context, ph)?;
    let dom = &dom[..len];
    let (a, prefix) = expanded(seed);
    let pk = encode(&base(&a));
    let r = S::reduce(&hash::<114>(&[dom, &prefix, message]), &ORDER);
    let encoded_r = encode(&base(&scalar_bytes(&r)));
    let k = S::reduce(&hash::<114>(&[dom, &encoded_r, &pk, message]), &ORDER);
    let s = k.mul_add(&S::reduce(&a, &ORDER), &r, &ORDER);
    let mut signature = [0; 114];
    signature[..57].copy_from_slice(&encoded_r);
    s.encode(&mut signature[57..]);
    Ok(signature)
}
/// BC-compatible Ed448 verification with cofactor clearing; oversized contexts fail.
pub fn verify(
    public_key: &[u8; 57],
    message: &[u8],
    signature: &[u8; 114],
    context: &[u8],
) -> bool {
    verify_inner(public_key, message, signature, context, false, false)
}
/// BC-compatible Ed448ph verification of a 64-byte SHAKE256 prehash.
pub fn verify_prehashed(
    public_key: &[u8; 57],
    prehash: &[u8; 64],
    signature: &[u8; 114],
    context: &[u8],
) -> bool {
    verify_inner(public_key, prehash, signature, context, true, false)
}
fn order_bytes() -> [u8; 57] {
    let mut out = [0; 57];
    for (i, w) in ORDER.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}
/// Validates canonical encoding, nonidentity and prime-subgroup membership.
pub fn validate_public_key(public_key: &[u8; 57]) -> bool {
    Point::decode(public_key)
        .is_some_and(|p| !p.is_identity() && p.multiply(&order_bytes()).is_identity())
}

/// Checks canonical encoding and rejects small-order public keys, matching BC's partial validation.
pub fn validate_public_key_partial(public_key: &[u8; 57]) -> bool {
    Point::decode(public_key).is_some_and(|p| !p.multiply(&[4]).is_identity())
}
/// Ed448 verification requiring nonidentity A and prime-subgroup A/R.
pub fn verify_strict(
    public_key: &[u8; 57],
    message: &[u8],
    signature: &[u8; 114],
    context: &[u8],
) -> bool {
    verify_inner(public_key, message, signature, context, false, true)
}
/// Ed448ph verification requiring prime-subgroup A/R.
pub fn verify_prehashed_strict(
    public_key: &[u8; 57],
    prehash: &[u8; 64],
    signature: &[u8; 114],
    context: &[u8],
) -> bool {
    verify_inner(public_key, prehash, signature, context, true, true)
}
fn verify_inner(
    pk: &[u8; 57],
    message: &[u8],
    signature: &[u8; 114],
    context: &[u8],
    ph: bool,
    strict: bool,
) -> bool {
    let Ok((dom, len)) = domain(context, ph) else {
        return false;
    };
    if !S::is_canonical(&signature[57..], &ORDER) {
        return false;
    }
    let Some(a) = Point::decode(pk) else {
        return false;
    };
    let Some(r) = Point::decode(&signature[..57]) else {
        return false;
    };
    if strict {
        if a.is_identity()
            || !a.multiply(&order_bytes()).is_identity()
            || !r.multiply(&order_bytes()).is_identity()
        {
            return false;
        }
    } else if a.multiply(&[4]).is_identity() {
        return false;
    }
    let k = S::reduce(
        &hash::<114>(&[&dom[..len], &signature[..57], pk, message]),
        &ORDER,
    );
    let mut left = base(signature[57..].try_into().unwrap());
    let mut right = r.add(&a.multiply(&scalar_bytes(&k)));
    if !strict {
        for _ in 0..2 {
            left = left.add(&left);
            right = right.add(&right);
        }
    }
    left.equals(&right)
}
