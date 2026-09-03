//! X25519 — RFC 7748 Diffie–Hellman on Curve25519 (Montgomery form).
//!
//! Ported from Bouncy Castle's `Org.BouncyCastle.Math.EC.Rfc7748.X25519`. The core is
//! a constant-time Montgomery ladder over the [`Fe`] base field: given a clamped
//! scalar `k` and a `u`-coordinate, it computes `k · u` — the shared secret.
//!
//! [`Fe`]: super::x25519_field::Fe

use super::x25519_field::Fe;

/// Byte length of a `u`-coordinate / output point (RFC 7748 `PointSize`).
pub const POINT_SIZE: usize = 32;
/// Byte length of a scalar / private key (RFC 7748 `ScalarSize`).
pub const SCALAR_SIZE: usize = 32;

/// Curve25519 Montgomery coefficient `A = 486662` (`By² = x³ + Ax² + x`). bc `C_A`.
const C_A: i32 = 486662;
/// The ladder constant `a24 = (A + 2) / 4 = 121666`. bc `C_A24`; the `× a24` step uses
/// [`Fe::mul_i32`](super::x25519_field::Fe::mul_i32).
const C_A24: i32 = (C_A + 2) / 4;

const _: () = assert!(C_A24 == 121666);

/// Montgomery point doubling in `(X:Z)` projective coordinates: `2·(x:z)`. Corresponds
/// to bc `X25519.PointDouble`.
///
/// `X₂ = (x+z)²(x−z)²`, `Z₂ = 4xz·((x−z)² + a24·4xz)` — all via [`Fe`] operations.
fn point_double(x: Fe, z: Fe) -> (Fe, Fe) {
    let (a, b) = x.apm(z); // a = x+z, b = x−z
    let a = a.sqr(); // (x+z)²
    let b = b.sqr(); // (x−z)²
    let x2 = a.mul(b); // X₂ = (x+z)²(x−z)²
    let a = a.sub(b); // 4xz
    let z = a.mul_i32(C_A24); // 4xz·a24
    let z = z.add(b); // 4xz·a24 + (x−z)²
    let z2 = z.mul(a); // Z₂
    (x2, z2)
}

/// Decodes a 32-byte scalar into 8 little-endian `u32` words and applies RFC 7748
/// **clamping**: clear the low 3 bits (cofactor), clear the top bit, and set bit 254.
/// Corresponds to bc `X25519.DecodeScalar` (which folds the clamp of `ClampPrivateKey`
/// into the word-level decode).
fn decode_scalar(k: &[u8; SCALAR_SIZE]) -> [u32; 8] {
    let mut n = [0u32; 8];
    for (i, w) in n.iter_mut().enumerate() {
        *w = u32::from_le_bytes(k[i * 4..i * 4 + 4].try_into().unwrap());
    }
    n[0] &= 0xFFFF_FFF8; // 清低 3 位
    n[7] &= 0x7FFF_FFFF; // 清最高位
    n[7] |= 0x4000_0000; // 設 bit 254
    n
}

/// X25519 scalar multiplication (RFC 7748): given a 32-byte scalar `k` and a 32-byte
/// `u`-coordinate, returns `k · u` as 32 bytes — the Diffie–Hellman shared secret.
///
/// Constant-time: a Montgomery ladder over [`Fe`] with `cswap`-driven, bit-independent
/// control flow. Corresponds to bc `X25519.ScalarMult`, transcribed verbatim.
pub fn scalar_mult(k: &[u8; SCALAR_SIZE], u: &[u8; POINT_SIZE]) -> [u8; POINT_SIZE] {
    let n = decode_scalar(k);
    let x1 = Fe::decode(u);
    let mut x2 = x1;
    let mut z2 = Fe::one();
    let mut x3 = Fe::one();
    let mut z3 = Fe::zero();
    debug_assert_eq!(n[7] >> 30, 1);

    let mut bit = 254i32;
    let mut swap = 1i32;
    loop {
        let (t1, nx3) = x3.apm(z3); // t1 = x3+z3; x3 = x3−z3
        x3 = nx3;
        let (nz3, nx2) = x2.apm(z2); // z3 = x2+z2; x2 = x2−z2
        z3 = nz3;
        x2 = nx2;
        let t1 = t1.mul(x2); // (x3+z3)(x2−z2)
        x3 = x3.mul(z3); // (x3−z3)(x2+z2)
        z3 = z3.sqr(); // (x2+z2)²
        x2 = x2.sqr(); // (x2−z2)²

        let t2 = z3.sub(x2); // 4·x2·z2
        z2 = t2.mul_i32(C_A24);
        z2 = z2.add(x2);
        z2 = z2.mul(t2); // new z2
        x2 = x2.mul(z3); // new x2

        let (nx3b, nz3b) = t1.apm(x3); // x3 = t1+x3; z3 = t1−x3
        x3 = nx3b;
        z3 = nz3b;
        x3 = x3.sqr(); // new x3
        z3 = z3.sqr();
        z3 = z3.mul(x1); // new z3

        bit -= 1;
        let word = (bit >> 5) as usize;
        let shift = bit & 0x1F;
        let kt = ((n[word] >> shift) & 1) as i32;
        swap ^= kt;
        (x2, x3) = Fe::cswap(swap, x2, x3);
        (z2, z3) = Fe::cswap(swap, z2, z3);
        swap = kt;

        if bit < 3 {
            break;
        }
    }
    debug_assert_eq!(swap, 0);

    // 尾端 3 次倍點 = ×8（clamp 已把低 3 位清零 → cofactor 清除）。
    for _ in 0..3 {
        (x2, z2) = point_double(x2, z2);
    }

    let x2 = x2.mul(z2.invert()); // affine u = x2 / z2
    x2.normalize().encode()
}

//
// TODO(x25519-base): `ScalarMultBase` (public key from private key) uses the Edwards
// base-point mult (bc routes it through Ed25519), so it depends on the rfc8032 line —
// deferred until Ed25519 exists. (The generic ladder with u = 9 also works.)

#[cfg(test)]
mod tests {
    use super::*;
    use crate::big_integer::BigInteger;

    fn p() -> BigInteger {
        &(&BigInteger::from_u32(1) << 255) - &BigInteger::from_u32(19)
    }
    fn val(f: Fe) -> BigInteger {
        BigInteger::from_bytes_le_unsigned(&f.normalize().encode())
    }

    #[test]
    fn point_double_matches_montgomery_formula() {
        let p = p();
        let one = BigInteger::from_u32(1);
        let a = BigInteger::from_u32(C_A as u32); // 486662
        let u = Fe::decode(&[
            0x09, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0,
            0xD0, 0xE0, 0xF0, 0x00,
        ]);

        // point_double 的 affine 結果 u' = X₂ / Z₂
        let (x2, z2) = point_double(u, Fe::one());
        let got = val(x2.mul(z2.invert()));

        // 參考:u' = (u²−1)² / (4u(u²+Au+1)) mod p
        let uv = val(u);
        let u2 = (&uv * &uv).rem_euclid(&p);
        let num0 = (&u2 - &one).rem_euclid(&p);
        let num = (&num0 * &num0).rem_euclid(&p); // (u²−1)²
        let inner = (&(&u2 + &(&a * &uv)) + &one).rem_euclid(&p); // u²+Au+1
        let den = (&(&BigInteger::from_u32(4) * &uv) * &inner).rem_euclid(&p); // 4u(...)
        let expected = (&num * &den.mod_inverse(&p).unwrap()).rem_euclid(&p);

        assert_eq!(got, expected);
    }

    #[test]
    fn decode_scalar_clamps() {
        // 全 0xFF：n[0] 清低 3 位、n[7] 清最高位（bit 254 本就在 0x7FFFFFFF 內）
        let n = decode_scalar(&[0xFF; 32]);
        assert_eq!(n[0], 0xFFFF_FFF8);
        assert_eq!(n[7], 0x7FFF_FFFF);
        assert_eq!(&n[1..7], &[0xFFFF_FFFFu32; 6]);
        // 全 0：n[7] 設 bit 254
        let n = decode_scalar(&[0x00; 32]);
        assert_eq!(n[0], 0);
        assert_eq!(n[7], 0x4000_0000);
        // little-endian 讀取:bytes 1,2,3,4 → 0x04030201，再 &0xFFFFFFF8
        let mut k = [0u8; 32];
        k[0] = 1;
        k[1] = 2;
        k[2] = 3;
        k[3] = 4;
        assert_eq!(decode_scalar(&k)[0], 0x0403_0201 & 0xFFFF_FFF8);
    }

    // 32-byte hex → [u8;32]。
    fn hb(s: &str) -> [u8; 32] {
        let mut b = [0u8; 32];
        for (i, byte) in b.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        b
    }

    #[test]
    fn rfc7748_scalar_mult_vectors() {
        // RFC 7748 §5.2 兩組官方測試向量。
        let k1 = hb("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u1 = hb("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let r1 = hb("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        assert_eq!(scalar_mult(&k1, &u1), r1);

        let k2 = hb("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let u2 = hb("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        let r2 = hb("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
        assert_eq!(scalar_mult(&k2, &u2), r2);
    }
}
