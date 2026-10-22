// RFC 8032 Ed448：私鑰在 init 時展開一次；雜湊是 SHAKE256，每個簽章都帶 dom4 的 context。
// 驗章照 BC：標準編碼、拒絕小階公鑰、乘上 cofactor 4 後比對。

use crate::CfrgError;
use crate::edwards::{EdwardsPoint, Scalar};
use crate::rfc7748::x448_field::Fe448;
use rand_core::CryptoRng;
use tc_digest::{Digest, Xof};
use tc_keccak::ShakeDigest;
use tc_zeroize::Zeroize;

pub(crate) const SIGNATURE_SIZE: usize = 114;

const ORDER: [u32; 14] = [
    0xab5844f3, 0x2378c292, 0x8dc58f55, 0x216cc272, 0xaed63690, 0xc44edb49, 0x7cca23e9, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x3fffffff,
];

// 基點 B 的標準編碼，取自 BC Ed448.cs 的 radix-2^28 常數；B_x 為偶數。
const BASE: [u8; 57] = [
    0x14, 0xfa, 0x30, 0xf2, 0x5b, 0x79, 0x08, 0x98, 0xad, 0xc8, 0xd7, 0x4e, 0x2c, 0x13, 0xbd, 0xfd,
    0xc4, 0x39, 0x7c, 0xe6, 0x1c, 0xff, 0xd3, 0x3a, 0xd7, 0xc2, 0xa0, 0x05, 0x1e, 0x9c, 0x78, 0x87,
    0x40, 0x98, 0xa3, 0x6c, 0x73, 0x73, 0xea, 0x4b, 0x62, 0xc7, 0xc9, 0x56, 0x37, 0x20, 0x76, 0x88,
    0x24, 0xbc, 0xb6, 0x6e, 0x71, 0x46, 0x3f, 0x69, 0x00,
];

type Point = EdwardsPoint<Fe448>;
type S = Scalar<14>;

// RFC 8032 §5.2.5：k 的 SHAKE256 前半 prune 成純量 s，後半是 prefix，公鑰 A = [s]B。
pub(crate) struct ExpandedKey {
    s: [u8; 57],
    prefix: [u8; 57],
    public_key: [u8; 57],
}

impl ExpandedKey {
    pub(crate) fn new(k: &[u8; 57]) -> Self {
        let mut h = hash::<114>(&[k]);
        let mut s = [0; 57];
        s.copy_from_slice(&h[..57]);
        s[0] &= 252;
        s[55] |= 128;
        s[56] = 0;
        let mut prefix = [0; 57];
        prefix.copy_from_slice(&h[57..]);
        h.zeroize();
        let public_key = encode(&base(&s));
        Self {
            s,
            prefix,
            public_key,
        }
    }

    pub(crate) fn public_key(&self) -> &[u8; 57] {
        &self.public_key
    }
}

impl Drop for ExpandedKey {
    fn drop(&mut self) {
        self.s.zeroize();
        self.prefix.zeroize();
    }
}

pub(crate) fn generate_private_key<R: CryptoRng + ?Sized>(rng: &mut R) -> [u8; 57] {
    let mut k = [0; 57];
    rng.fill_bytes(&mut k);
    k
}

// dom4(F, C)：Ed448 一律帶上，context 最長 255 位元組，可以是空的。
pub(crate) fn domain(context: &[u8], ph: bool) -> Result<([u8; 265], usize), CfrgError> {
    if context.len() > 255 {
        return Err(CfrgError::ContextTooLong);
    }
    let mut bytes = [0; 265];
    bytes[..8].copy_from_slice(b"SigEd448");
    bytes[8] = ph as u8;
    bytes[9] = context.len() as u8;
    bytes[10..10 + context.len()].copy_from_slice(context);
    Ok((bytes, 10 + context.len()))
}

pub(crate) fn sign(key: &ExpandedKey, dom: &[u8], message: &[u8]) -> [u8; SIGNATURE_SIZE] {
    let r = S::reduce(&hash::<114>(&[dom, &key.prefix, message]), &ORDER);
    let encoded_r = encode(&base(&scalar_bytes(&r)));
    let k = S::reduce(
        &hash::<114>(&[dom, &encoded_r, &key.public_key, message]),
        &ORDER,
    );
    let s = k.mul_add(&S::reduce(&key.s, &ORDER), &r, &ORDER);
    let mut signature = [0; SIGNATURE_SIZE];
    signature[..57].copy_from_slice(&encoded_r);
    s.encode(&mut signature[57..]);
    signature
}

// BC 的部分驗證：標準編碼，且不是小階點。
pub(crate) fn validate_public_key_partial(public_key: &[u8; 57]) -> bool {
    Point::decode(public_key).is_some_and(|p| !p.multiply(&[4]).is_identity())
}

pub(crate) fn verify(
    public_key: &[u8; 57],
    dom: &[u8],
    message: &[u8],
    signature: &[u8; SIGNATURE_SIZE],
) -> bool {
    if !S::is_canonical(&signature[57..], &ORDER) {
        return false;
    }
    let Some(a) = Point::decode(public_key) else {
        return false;
    };
    let Some(r) = Point::decode(&signature[..57]) else {
        return false;
    };
    if a.multiply(&[4]).is_identity() {
        return false;
    }
    let k = S::reduce(
        &hash::<114>(&[dom, &signature[..57], public_key, message]),
        &ORDER,
    );
    let mut s = [0; 57];
    s.copy_from_slice(&signature[57..]);
    let mut left = base(&s);
    let mut right = r.add(&a.multiply(&scalar_bytes(&k)));
    for _ in 0..2 {
        left = left.add(&left);
        right = right.add(&right);
    }
    left.equals(&right)
}

fn hash<const N: usize>(parts: &[&[u8]]) -> [u8; N] {
    let mut digest = ShakeDigest::new(256);
    for part in parts {
        digest.update(part);
    }
    let mut output = [0; N];
    digest.output_final(&mut output);
    output
}

fn base(scalar: &[u8; 57]) -> Point {
    Point::decode(&BASE)
        .expect("the Ed448 generator decodes")
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
