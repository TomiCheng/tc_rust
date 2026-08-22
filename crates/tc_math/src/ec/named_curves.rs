//! Standard named elliptic curves (parameter tables + builders).
//!
//! A lightweight stand-in for Bouncy Castle's `ECNamedCurveTable` / `SecNamedCurves`:
//! it holds the published parameters of well-known curves and builds a ready-to-use
//! curve plus its base point. No ASN.1 / X9 / OID machinery — just the field
//! parameters, `a`, `b`, order `n`, cofactor `h`, and the encoded base point `G`.
//!
//! Because `FpCurve` and `F2mCurve` are distinct concrete types (there is no common
//! `EcCurve` trait yet — that is deferred until generic curve algorithms need it),
//! each curve is exposed as its own function returning the concrete `(Arc<curve>,
//! point)` pair, rather than a single heterogeneous `by_name` table.

use alloc::sync::Arc;

use crate::big_integer::BigInteger;
use crate::ec::f2m_curve::F2mCurve;
use crate::ec::f2m_point::F2mPoint;
use crate::ec::fp_curve::FpCurve;
use crate::ec::fp_point::FpPoint;

/// The SEC 2 **secp256k1** curve (`y² = x³ + 7` over GF(p)), with its base point `G`.
///
/// Returns `(Arc<FpCurve>, G)`; the curve carries the group order `n` and cofactor
/// `h = 1`.
pub fn secp256k1() -> (Arc<FpCurve>, FpPoint) {
    // p = 2^256 − 2^32 − 977
    let p = h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    let n = h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    let curve = Arc::new(FpCurve::new(
        p,
        BigInteger::from_u32(0),       // a = 0
        BigInteger::from_u32(7),       // b = 7
        Some(n),                       // 群階 n
        Some(BigInteger::from_u32(1)), // cofactor h = 1
    ));
    let gx = h("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
    let gy = h("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
    let g = curve.create_point(gx, gy);
    (curve, g)
}

/// The SEC 2 **secp256r1** curve — NIST **P-256** — (`y² = x³ + ax + b` over GF(p)),
/// with its base point `G`. `a = p − 3`; cofactor `h = 1`.
///
/// Its prime is byte-aligned with a non-all-ones top word, so field reduction takes
/// the Barrett path (unlike secp256k1's pseudo-Mersenne).
pub fn secp256r1() -> (Arc<FpCurve>, FpPoint) {
    // p = 2^224·(2^32 − 1) + 2^192 + 2^96 − 1
    let p = h("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
    let a = h("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"); // p − 3
    let b = h("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
    let n = h("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    let curve = Arc::new(FpCurve::new(p, a, b, Some(n), Some(BigInteger::from_u32(1))));
    let gx = h("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
    let gy = h("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
    let g = curve.create_point(gx, gy);
    (curve, g)
}

/// The SEC 2 **sect163k1** Koblitz curve (`y² + xy = x³ + x² + 1` over GF(2¹⁶³),
/// reduced by `x¹⁶³ + x⁷ + x⁶ + x³ + 1`), with its base point `G`. `a = b = 1`;
/// cofactor `h = 2`.
pub fn sect163k1() -> (Arc<F2mCurve>, F2mPoint) {
    let n = h("04000000000000000000020108A2E0CC0D99F8A5EF");
    let curve = Arc::new(F2mCurve::pentanomial(
        163,
        3,
        6,
        7,
        BigInteger::from_u32(1),       // a = 1
        BigInteger::from_u32(1),       // b = 1
        Some(n),                       // 群階 n
        Some(BigInteger::from_u32(2)), // cofactor h = 2
    ));
    let gx = h("02FE13C0537BBC11ACAA07D793DE4E6D5E5C94EEE8");
    let gy = h("0289070FB05D38FF58321F2E800536D538CCDAA3D9");
    let g = curve.create_point(gx, gy);
    (curve, g)
}

/// 16 進位字串 → BigInteger（模組內小工具，供各命名曲線共用）。
fn h(s: &str) -> BigInteger {
    BigInteger::from_str_radix(s, 16).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secp256k1_n_times_g_is_infinity() {
        let (c, g) = secp256k1();
        assert_eq!(c.field_size(), 256);
        // 基點非無窮遠；n·G = O（驗參數正確）。
        assert!(!g.is_infinity());
        assert!((&g * c.order().unwrap()).is_infinity());
    }

    #[test]
    fn secp256k1_base_point_roundtrips() {
        let (c, g) = secp256k1();
        // 壓縮/未壓縮 encode → decode 都回原基點。
        for compressed in [false, true] {
            assert_eq!(c.decode_point(&g.encode(compressed)).unwrap(), g);
        }
    }

    #[test]
    fn secp256r1_n_times_g_is_infinity() {
        let (c, g) = secp256r1();
        assert_eq!(c.field_size(), 256);
        assert!(!g.is_infinity());
        assert!((&g * c.order().unwrap()).is_infinity()); // n·G = O（Barrett 約簡路徑）
    }

    #[test]
    fn secp256r1_base_point_roundtrips() {
        let (c, g) = secp256r1();
        for compressed in [false, true] {
            assert_eq!(c.decode_point(&g.encode(compressed)).unwrap(), g);
        }
    }

    #[test]
    fn sect163k1_n_times_g_is_infinity() {
        let (c, g) = sect163k1();
        assert_eq!(c.field_size(), 163);
        assert!(!g.is_infinity());
        assert!((&g * c.order().unwrap()).is_infinity()); // n·G = O
    }

    #[test]
    fn sect163k1_base_point_roundtrips() {
        let (c, g) = sect163k1();
        // F2m 壓縮走 decompress（half_trace）。
        for compressed in [false, true] {
            assert_eq!(c.decode_point(&g.encode(compressed)).unwrap(), g);
        }
    }
}
