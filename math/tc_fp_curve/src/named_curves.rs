//! Step 2 驗證用的兩條 256-bit 具名質數曲線。
//!
//! 此模組只帶 secp256k1 與 secp256r1；其餘具名曲線仍留在舊 `tc_ec`，
//! 避免這次 Fp 拆分擴張到完整 registry。

use alloc::sync::Arc;

use tc_bigint::BigUint;

use crate::{FpCurve, FpPoint};

/// 建立 SEC 2 secp256k1 與基點 `G`。
pub fn secp256k1() -> (Arc<FpCurve>, FpPoint) {
    let p = hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    let order = hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    let curve = Arc::new(FpCurve::new(
        p,
        BigUint::from(0_u8),
        BigUint::from(7_u8),
        Some(order),
        Some(BigUint::from(1_u8)),
    ));
    let point = curve.create_point(
        hex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
        hex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
    );
    (curve, point)
}

/// 建立 SEC 2 secp256r1（NIST P-256）與基點 `G`。
pub fn secp256r1() -> (Arc<FpCurve>, FpPoint) {
    let p = hex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
    let a = hex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");
    let b = hex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
    let order = hex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    let curve = Arc::new(FpCurve::new(
        p,
        a,
        b,
        Some(order),
        Some(BigUint::from(1_u8)),
    ));
    let point = curve.create_point(
        hex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
        hex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"),
    );
    (curve, point)
}

fn hex(value: &str) -> BigUint {
    BigUint::from_str_radix(value, 16).expect("named-curve constant is valid hex")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tc_bigint_old::BigInt;

    fn assert_matches_old(
        new_curve: &(Arc<FpCurve>, FpPoint),
        old_curve: &(alloc::sync::Arc<tc_ec::FpCurve>, tc_ec::FpPoint),
    ) {
        let (_, new_g) = new_curve;
        let (_, old_g) = old_curve;
        assert!(new_g.is_valid());
        assert_eq!(new_g.encode(false), old_g.encode(false));

        let new_double = new_g.twice();
        let old_double = old_g.twice();
        assert_eq!(new_double.encode(false), old_double.encode(false));
        assert_eq!(
            (&new_double + new_g).encode(false),
            (&old_double + old_g).encode(false)
        );

        for scalar in [3_u32, 19, 255] {
            let new_result = new_g.mul_double_and_add(&BigUint::from(scalar));
            let old_result = old_g.mul_double_and_add(&BigInt::from_u32(scalar));
            assert_eq!(
                new_result.encode(false),
                old_result.encode(false),
                "scalar {scalar}"
            );
        }
    }

    #[test]
    fn secp256_curves_match_the_old_tc_ec_oracle() {
        assert_matches_old(&secp256k1(), &tc_ec::ec::named_curves::secp256k1());
        assert_matches_old(&secp256r1(), &tc_ec::ec::named_curves::secp256r1());
    }

    #[test]
    fn named_points_round_trip_both_sec_encodings() {
        for (curve, point) in [secp256k1(), secp256r1()] {
            for compressed in [false, true] {
                let encoded = point.encode(compressed);
                assert_eq!(curve.decode_point(&encoded).unwrap(), point);
            }
        }
    }
}
