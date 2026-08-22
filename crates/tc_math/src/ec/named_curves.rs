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
}
