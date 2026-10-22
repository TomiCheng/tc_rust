// RFC 8032 Ed25519：私鑰在 init 時展開一次，簽章只做兩次 SHA-512 與兩次固定基點乘法。
// 驗章照 BC：標準編碼、拒絕小階公鑰、乘上 cofactor 後比對。

use crate::CfrgError;
use crate::edwards::{EdwardsPoint, Scalar};
use crate::rfc7748::ed25519_base::scalar_mult_base;
use crate::rfc7748::x25519_field::Fe;
use rand_core::CryptoRng;
use tc_digest::Digest;
use tc_sha::Sha512Digest;
use tc_zeroize::Zeroize;

pub(crate) const SIGNATURE_SIZE: usize = 64;

const ORDER: [u32; 8] = [
    0x5cf5d3ed, 0x5812631a, 0xa2f79cd6, 0x14def9de, 0, 0, 0, 0x10000000,
];

type Point = EdwardsPoint<Fe>;
type S = Scalar<8>;

// RFC 8032 §5.1.5：k 的 SHA-512 前半 prune 成純量 s，後半是 prefix，公鑰 A = [s]B。
pub(crate) struct ExpandedKey {
    s: [u8; 32],
    prefix: [u8; 32],
    public_key: [u8; 32],
}

impl ExpandedKey {
    pub(crate) fn new(k: &[u8; 32]) -> Self {
        let mut h = hash(&[k]);
        let mut s = [0; 32];
        s.copy_from_slice(&h[..32]);
        s[0] &= 248;
        s[31] &= 63;
        s[31] |= 64;
        let mut prefix = [0; 32];
        prefix.copy_from_slice(&h[32..]);
        h.zeroize();
        let public_key = encode(&base(&s));
        Self {
            s,
            prefix,
            public_key,
        }
    }

    pub(crate) fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
}

impl Drop for ExpandedKey {
    fn drop(&mut self) {
        self.s.zeroize();
        self.prefix.zeroize();
    }
}

pub(crate) fn generate_private_key<R: CryptoRng + ?Sized>(rng: &mut R) -> [u8; 32] {
    let mut k = [0; 32];
    rng.fill_bytes(&mut k);
    k
}

// dom2(F, C)：pure Ed25519 沒有前綴，ctx 與 ph 帶 context，最長 255 位元組。
pub(crate) fn domain(context: Option<&[u8]>, ph: bool) -> Result<([u8; 289], usize), CfrgError> {
    let mut bytes = [0; 289];
    let Some(context) = context else {
        return Ok((bytes, 0));
    };
    if context.len() > 255 {
        return Err(CfrgError::ContextTooLong);
    }
    bytes[..32].copy_from_slice(b"SigEd25519 no Ed25519 collisions");
    bytes[32] = ph as u8;
    bytes[33] = context.len() as u8;
    bytes[34..34 + context.len()].copy_from_slice(context);
    Ok((bytes, 34 + context.len()))
}

pub(crate) fn sign(key: &ExpandedKey, dom: &[u8], message: &[u8]) -> [u8; SIGNATURE_SIZE] {
    let r = S::reduce(&hash(&[dom, &key.prefix, message]), &ORDER);
    let encoded_r = encode(&base(&scalar_bytes(&r)));
    let k = S::reduce(&hash(&[dom, &encoded_r, &key.public_key, message]), &ORDER);
    let s = k.mul_add(&S::reduce(&key.s, &ORDER), &r, &ORDER);
    let mut signature = [0; SIGNATURE_SIZE];
    signature[..32].copy_from_slice(&encoded_r);
    s.encode(&mut signature[32..]);
    signature
}

// BC 的部分驗證：標準編碼，且不是小階點。
pub(crate) fn validate_public_key_partial(public_key: &[u8; 32]) -> bool {
    Point::decode(public_key).is_some_and(|p| !p.multiply(&[8]).is_identity())
}

pub(crate) fn verify(
    public_key: &[u8; 32],
    dom: &[u8],
    message: &[u8],
    signature: &[u8; SIGNATURE_SIZE],
) -> bool {
    if !S::is_canonical(&signature[32..], &ORDER) {
        return false;
    }
    let Some(a) = Point::decode(public_key) else {
        return false;
    };
    let Some(r) = Point::decode(&signature[..32]) else {
        return false;
    };
    if a.multiply(&[8]).is_identity() {
        return false;
    }
    let k = S::reduce(&hash(&[dom, &signature[..32], public_key, message]), &ORDER);
    let mut s = [0; 32];
    s.copy_from_slice(&signature[32..]);
    let mut left = base(&s);
    let mut right = r.add(&a.multiply(&scalar_bytes(&k)));
    for _ in 0..3 {
        left = left.add(&left);
        right = right.add(&right);
    }
    left.equals(&right)
}

fn hash(parts: &[&[u8]]) -> [u8; 64] {
    let mut digest = Sha512Digest::new();
    for part in parts {
        digest.update(part);
    }
    let mut output = [0; 64];
    digest.do_final(&mut output);
    output
}

fn base(scalar: &[u8; 32]) -> Point {
    let (x, y, z, t) = scalar_mult_base(scalar);
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
