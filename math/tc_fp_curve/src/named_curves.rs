//! 驗證用的兩條 256-bit 具名質數曲線。
//!
//! 此模組只帶 secp256k1 與 secp256r1；其餘具名曲線仍留在舊 `tc_ec`，
//! 避免這次 Fp 拆分擴張到完整 registry。無後綴函式使用固定寬度 `U256`，
//! `_dynamic` 版本保留 `BigUint` 具體化以供交叉驗證。

use alloc::sync::Arc;

use tc_bigint::{BigUint, U256};

use crate::{FpCurve, FpInteger, FpPoint};

/// 建立固定寬度 SEC 2 secp256k1 與基點 `G`。
pub fn secp256k1() -> (Arc<FpCurve<U256>>, FpPoint<U256>) {
    secp256k1_with()
}

/// 建立動態寬度 SEC 2 secp256k1 與基點 `G`。
pub fn secp256k1_dynamic() -> (Arc<FpCurve<BigUint>>, FpPoint<BigUint>) {
    secp256k1_with()
}

/// 以指定 Fp 整數表示建立 SEC 2 secp256k1 與基點 `G`。
pub fn secp256k1_with<B: FpInteger>() -> (Arc<FpCurve<B>>, FpPoint<B>) {
    let p = hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    let order = hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    let curve = Arc::new(FpCurve::new(
        p,
        integer(0),
        integer(7),
        Some(order),
        Some(integer(1)),
    ));
    let point = curve.create_point(
        hex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
        hex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
    );
    (curve, point)
}

/// 建立固定寬度 SEC 2 secp256r1（NIST P-256）與基點 `G`。
pub fn secp256r1() -> (Arc<FpCurve<U256>>, FpPoint<U256>) {
    secp256r1_with()
}

/// 建立動態寬度 SEC 2 secp256r1（NIST P-256）與基點 `G`。
pub fn secp256r1_dynamic() -> (Arc<FpCurve<BigUint>>, FpPoint<BigUint>) {
    secp256r1_with()
}

/// 以指定 Fp 整數表示建立 SEC 2 secp256r1 與基點 `G`。
pub fn secp256r1_with<B: FpInteger>() -> (Arc<FpCurve<B>>, FpPoint<B>) {
    let p = hex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
    let a = hex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");
    let b = hex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
    let order = hex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    let curve = Arc::new(FpCurve::new(p, a, b, Some(order), Some(integer(1))));
    let point = curve.create_point(
        hex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
        hex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"),
    );
    (curve, point)
}

fn hex<B: FpInteger>(value: &str) -> B {
    match B::from_str_radix(value, 16) {
        Ok(value) => value,
        Err(_) => panic!("named-curve constant is valid hex"),
    }
}

fn integer<B: FpInteger>(value: u8) -> B {
    B::from_u8(value).expect("named-curve small constant fits")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tc_bigint_old::BigInt;

    fn assert_matches_old<B: FpInteger>(
        new_curve: &(Arc<FpCurve<B>>, FpPoint<B>),
        old_curve: &(alloc::sync::Arc<tc_ec::FpCurve>, tc_ec::FpPoint),
        seed: u64,
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
            let new_scalar = B::from_u32(scalar).expect("small scalar fits");
            let new_result = new_g.mul_double_and_add(&new_scalar);
            let old_result = old_g.mul_double_and_add(&BigInt::from_u32(scalar));
            assert_eq!(
                new_result.encode(false),
                old_result.encode(false),
                "scalar {scalar}"
            );
        }

        // 以固定種子產生可重現的 256-bit 純量；先乘出隨機有效點，再以另一份
        // 完整寬度純量交叉驗證，避免測試只覆蓋生成點與最低 8 bits。
        let mut state = seed;
        let point_scalar_bytes = random_256_bits(&mut state);
        let scalar_bytes = random_256_bits(&mut state);
        let point_scalar = decode_integer::<B>(&point_scalar_bytes);
        let scalar = decode_integer::<B>(&scalar_bytes);
        assert_eq!(point_scalar.bit_length(), 256);
        assert_eq!(scalar.bit_length(), 256);

        let old_point_scalar = BigInt::from_bytes_be_unsigned(&point_scalar_bytes);
        let old_scalar = BigInt::from_bytes_be_unsigned(&scalar_bytes);
        let new_point = new_g.mul_double_and_add(&point_scalar);
        let old_point = old_g.mul_double_and_add(&old_point_scalar);
        assert_eq!(new_point.encode(false), old_point.encode(false));

        let new_result = new_point.mul_double_and_add(&scalar);
        let old_result = old_point.mul_double_and_add(&old_scalar);
        assert_eq!(new_result.encode(false), old_result.encode(false));
    }

    fn decode_integer<B: FpInteger>(bytes: &[u8]) -> B {
        match B::from_be_bytes(bytes) {
            Ok(value) => value,
            Err(_) => panic!("256-bit test scalar fits selected backend"),
        }
    }

    fn random_256_bits(state: &mut u64) -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        for chunk in bytes.chunks_mut(8) {
            *state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            chunk.copy_from_slice(&state.to_be_bytes());
        }
        bytes[0] |= 0x80;
        bytes
    }

    fn assert_round_trips<B: FpInteger>(curve: Arc<FpCurve<B>>, point: FpPoint<B>) {
        for compressed in [false, true] {
            let encoded = point.encode(compressed);
            assert_eq!(curve.decode_point(&encoded).unwrap(), point);
        }
    }

    #[test]
    fn secp256_curves_match_the_old_tc_ec_oracle() {
        let old_k1 = tc_ec::ec::named_curves::secp256k1();
        let old_r1 = tc_ec::ec::named_curves::secp256r1();
        assert_matches_old(&secp256k1(), &old_k1, 0x4B31_C0DE_2560_0001);
        assert_matches_old(&secp256k1_dynamic(), &old_k1, 0x4B31_C0DE_2560_0001);
        assert_matches_old(&secp256r1(), &old_r1, 0x5231_C0DE_2560_0001);
        assert_matches_old(&secp256r1_dynamic(), &old_r1, 0x5231_C0DE_2560_0001);
    }

    #[test]
    fn named_points_round_trip_both_sec_encodings() {
        for (curve, point) in [secp256k1(), secp256r1()] {
            assert_round_trips(curve, point);
        }
        for (curve, point) in [secp256k1_dynamic(), secp256r1_dynamic()] {
            assert_round_trips(curve, point);
        }
    }
}
