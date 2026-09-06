//! X25519 — RFC 7748 Diffie–Hellman on Curve25519 (Montgomery form).
//!
//! Ported from Bouncy Castle's `Org.BouncyCastle.Math.EC.Rfc7748.X25519`. The core is
//! a constant-time Montgomery ladder over the [`Fe`] base field: given a clamped
//! scalar `k` and a `u`-coordinate, it computes `k · u` — the shared secret.
//!
//! [`Fe`]: super::x25519_field::Fe

use super::x25519_field::Fe;
use rand_core::CryptoRng;

/// Byte length of a `u`-coordinate / output point (RFC 7748 `PointSize`).
pub const POINT_SIZE: usize = 32;
/// Byte length of a scalar / private key (RFC 7748 `ScalarSize`).
pub const SCALAR_SIZE: usize = 32;

/// RFC 7748 所定義的 X25519 基點 `u = 9`。
const BASE_POINT: [u8; POINT_SIZE] = {
    let mut point = [0_u8; POINT_SIZE];
    point[0] = 9;
    point
};

/// Curve25519 Montgomery coefficient `A = 486662` (`By² = x³ + Ax² + x`). bc `C_A`.
const C_A: i32 = 486662;
/// The ladder constant `a24 = (A + 2) / 4 = 121666`. bc `C_A24`; the `× a24` step uses
/// [`Fe::mul_i32`](super::x25519_field::Fe::mul_i32).
const C_A24: i32 = (C_A + 2) / 4;

const _: () = assert!(C_A24 == 121666);

/// 依 RFC 7748 section 5 夾制 X25519 私鑰。
///
/// 此操作會清除最低三位與最高位，並設定 bit 254。即使呼叫端傳入未夾制的
/// scalar，[`scalar_mult`] 也會在解碼時套用相同規則；公開這個函式是為了讓
/// 私鑰產生與儲存格式符合 RFC 7748。
pub fn clamp_private_key(private_key: &mut [u8; SCALAR_SIZE]) {
    private_key[0] &= 0xF8;
    private_key[SCALAR_SIZE - 1] &= 0x7F;
    private_key[SCALAR_SIZE - 1] |= 0x40;
}

/// 使用呼叫端提供的密碼學安全亂數來源產生已夾制的 X25519 私鑰。
///
/// crate 不自行取得系統熵；亂數來源與其生命週期完全由呼叫端控制。
pub fn generate_private_key<R: CryptoRng + ?Sized>(rng: &mut R) -> [u8; SCALAR_SIZE] {
    let mut private_key = [0_u8; SCALAR_SIZE];
    rng.fill_bytes(&mut private_key);
    clamp_private_key(&mut private_key);
    private_key
}

/// 從 X25519 私鑰產生公開鍵。
///
/// 目前固定基點乘法走通用 Montgomery ladder；之後接入 Ed25519 預算表時，
/// 可只替換 [`scalar_mult_base`] 的內部實作而不改公開 API。
pub fn generate_public_key(private_key: &[u8; SCALAR_SIZE]) -> [u8; POINT_SIZE] {
    scalar_mult_base(private_key)
}

/// 計算 X25519 Diffie-Hellman shared secret。
///
/// 回傳 `None` 代表結果全為零，也就是對方送入低階點；呼叫端必須拒絕這個
/// agreement。全零檢查會掃過完整輸出，不會在第一個非零 byte 提前結束。
pub fn calculate_agreement(
    private_key: &[u8; SCALAR_SIZE],
    peer_public_key: &[u8; POINT_SIZE],
) -> Option<[u8; POINT_SIZE]> {
    let agreement = scalar_mult(private_key, peer_public_key);
    let mut nonzero = 0_u8;
    for byte in agreement {
        nonzero |= byte;
    }
    if nonzero == 0 { None } else { Some(agreement) }
}

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

/// X25519 固定基點乘法。
///
/// 這是正確但較慢的通用 ladder fallback。Bouncy Castle 的最佳化版本會借用
/// Ed25519 的固定基點預算表；本 crate 尚未有 RFC 8032 實作，因此先直接以
/// RFC 7748 基點 `u = 9` 呼叫 [`scalar_mult`]。
pub fn scalar_mult_base(k: &[u8; SCALAR_SIZE]) -> [u8; POINT_SIZE] {
    scalar_mult(k, &BASE_POINT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::Infallible;
    use rand_core::{TryCryptoRng, TryRng};
    use tc_bigint_old::BigInt;

    struct SequenceRng(u8);

    impl TryRng for SequenceRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut bytes = [0_u8; 4];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u32::from_le_bytes(bytes))
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut bytes = [0_u8; 8];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u64::from_le_bytes(bytes))
        }

        fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
            for byte in output {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    impl TryCryptoRng for SequenceRng {}

    fn p() -> BigInt {
        &(&BigInt::from_u32(1) << 255) - &BigInt::from_u32(19)
    }
    fn val(f: Fe) -> BigInt {
        BigInt::from_bytes_le_unsigned(&f.normalize().encode())
    }

    #[test]
    fn point_double_matches_montgomery_formula() {
        let p = p();
        let one = BigInt::from_u32(1);
        let a = BigInt::from_u32(C_A as u32); // 486662
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
        let den = (&(&BigInt::from_u32(4) * &uv) * &inner).rem_euclid(&p); // 4u(...)
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

    #[test]
    fn public_clamp_matches_rfc7748() {
        let mut private_key = [0xFF; SCALAR_SIZE];
        clamp_private_key(&mut private_key);
        assert_eq!(private_key[0], 0xF8);
        assert_eq!(private_key[SCALAR_SIZE - 1], 0x7F);

        let mut private_key = [0_u8; SCALAR_SIZE];
        clamp_private_key(&mut private_key);
        assert_eq!(private_key[0], 0);
        assert_eq!(private_key[SCALAR_SIZE - 1], 0x40);
    }

    #[test]
    fn generated_private_key_uses_rng_then_clamps() {
        let private_key = generate_private_key(&mut SequenceRng(0));
        let mut expected = core::array::from_fn(|i| i as u8);
        clamp_private_key(&mut expected);
        assert_eq!(private_key, expected);
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

    #[test]
    fn rfc7748_iterated_vector_at_1000() {
        let mut k = [0_u8; POINT_SIZE];
        k[0] = 9;
        let mut u = k;

        for _ in 0..1_000 {
            let next = scalar_mult(&k, &u);
            u = k;
            k = next;
        }

        assert_eq!(
            k,
            hb("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")
        );
    }

    #[test]
    fn rfc7748_ecdh_public_api_vector() {
        let alice_private = hb("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_public = hb("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob_private = hb("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_public = hb("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let shared = hb("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        assert_eq!(generate_public_key(&alice_private), alice_public);
        assert_eq!(generate_public_key(&bob_private), bob_public);
        assert_eq!(
            calculate_agreement(&alice_private, &bob_public),
            Some(shared)
        );
        assert_eq!(
            calculate_agreement(&bob_private, &alice_public),
            Some(shared)
        );
    }

    #[test]
    fn agreement_rejects_all_zero_result() {
        let private_key = [0xA5; SCALAR_SIZE];
        assert_eq!(calculate_agreement(&private_key, &[0_u8; POINT_SIZE]), None);
    }

    #[test]
    fn scalar_mult_base_is_the_generic_base_point_ladder() {
        let private_key = hb("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        assert_eq!(
            scalar_mult_base(&private_key),
            scalar_mult(&private_key, &BASE_POINT)
        );
    }
}
