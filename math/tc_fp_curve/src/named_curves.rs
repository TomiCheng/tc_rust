//! SEC 2 泛型質數曲線。
//!
//! bc 沒有為 secp112r1、secp112r2 與 secp128r2 提供特化欄位，因此三者
//! 留在本泛型 Montgomery 層。256-bit 曲線則同時作為通用後端與特化曲線
//! 的參考實作。無後綴函式採固定寬度整數，`_dynamic` 使用 `BigUint`。

use alloc::sync::Arc;

use tc_bigint::{BigUint, U128, U256};

use crate::{FpCurve, FpInteger, FpPoint};

macro_rules! define_small_curve {
    ($name:ident, $dynamic:ident, $with:ident,
     $p:expr, $a:expr, $b:expr, $order:expr, $cofactor:expr, $gx:expr, $gy:expr) => {
        #[doc = concat!("建立固定寬度 SEC 2 `", stringify!($name), "` 與基點 `G`。")]
        #[deprecated(note = "cryptographically weak; interop/completeness only")]
        pub fn $name() -> (Arc<FpCurve<U128>>, FpPoint<U128>) {
            $with()
        }

        #[doc = concat!("建立動態寬度 SEC 2 `", stringify!($name), "` 與基點 `G`。")]
        #[deprecated(note = "cryptographically weak; interop/completeness only")]
        pub fn $dynamic() -> (Arc<FpCurve<BigUint>>, FpPoint<BigUint>) {
            $with()
        }

        #[doc = concat!("以指定 Fp 整數表示建立 SEC 2 `", stringify!($name), "`。")]
        pub fn $with<B: FpInteger>() -> (Arc<FpCurve<B>>, FpPoint<B>) {
            let curve = Arc::new(FpCurve::new(
                hex($p),
                hex($a),
                hex($b),
                Some(hex($order)),
                Some(integer($cofactor)),
            ));
            let point = curve.create_point(hex($gx), hex($gy));
            (curve, point)
        }
    };
}

define_small_curve!(
    secp112r1,
    secp112r1_dynamic,
    secp112r1_with,
    "DB7C2ABF62E35E668076BEAD208B",
    "DB7C2ABF62E35E668076BEAD2088",
    "659EF8BA043916EEDE8911702B22",
    "DB7C2ABF62E35E7628DFAC6561C5",
    1,
    "09487239995A5EE76B55F9C2F098",
    "A89CE5AF8724C0A23E0E0FF77500"
);
define_small_curve!(
    secp112r2,
    secp112r2_dynamic,
    secp112r2_with,
    "DB7C2ABF62E35E668076BEAD208B",
    "6127C24C05F38A0AAAF65C0EF02C",
    "51DEF1815DB5ED74FCC34C85D709",
    "36DF0AAFD8B8D7597CA10520D04B",
    4,
    "4BA30AB5E892B4E1649DD0928643",
    "ADCD46F5882E3747DEF36E956E97"
);
define_small_curve!(
    secp128r2,
    secp128r2_dynamic,
    secp128r2_with,
    "FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF",
    "D6031998D1B3BBFEBF59CC9BBFF9AEE1",
    "5EEEFCA380D02919DC2C6558BB6D8A5D",
    "3FFFFFFF7FFFFFFFBE0024720613B5A3",
    4,
    "7B6AA5D85E572983E6FB32A7CDEBC140",
    "27B6916A894D3AEE7106FE805FC34B44"
);

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
    B::from_str_radix(value, 16).unwrap_or_else(|_| panic!("named-curve constant is valid hex"))
}

fn integer<B: FpInteger>(value: u8) -> B {
    B::from_u8(value).expect("named-curve small constant fits")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tc_ec_core::CoordinateSystem;

    #[allow(clippy::too_many_arguments)]
    fn assert_parameters<B: FpInteger>(
        pair: &(Arc<FpCurve<B>>, FpPoint<B>),
        p: &str,
        a: &str,
        b: &str,
        order: &str,
        cofactor: u8,
        gx: &str,
        gy: &str,
    ) {
        let (curve, generator) = pair;
        assert_eq!(curve.q(), &hex(p));
        assert_eq!(curve.a().to_big_uint(), hex(a));
        assert_eq!(curve.b().to_big_uint(), hex(b));
        assert_eq!(curve.order(), Some(&hex(order)));
        assert_eq!(curve.cofactor(), Some(&integer(cofactor)));
        assert_eq!(generator.x().unwrap().to_big_uint(), hex(gx));
        assert_eq!(generator.y().unwrap().to_big_uint(), hex(gy));
        assert!(generator.is_valid());
    }

    fn assert_round_trips_and_order<B: FpInteger>(curve: Arc<FpCurve<B>>, point: FpPoint<B>) {
        for compressed in [false, true] {
            let encoded = point.encode(compressed);
            assert_eq!(curve.decode_point(&encoded).unwrap(), point);
        }
        assert!(
            point
                .mul_double_and_add(curve.order().expect("SEC curve has an order"))
                .is_infinity()
        );
    }

    #[allow(deprecated)]
    #[test]
    fn sec2_parameters_are_pinned_to_the_published_values() {
        assert_parameters(
            &secp112r1(),
            "DB7C2ABF62E35E668076BEAD208B",
            "DB7C2ABF62E35E668076BEAD2088",
            "659EF8BA043916EEDE8911702B22",
            "DB7C2ABF62E35E7628DFAC6561C5",
            1,
            "09487239995A5EE76B55F9C2F098",
            "A89CE5AF8724C0A23E0E0FF77500",
        );
        assert_parameters(
            &secp112r2(),
            "DB7C2ABF62E35E668076BEAD208B",
            "6127C24C05F38A0AAAF65C0EF02C",
            "51DEF1815DB5ED74FCC34C85D709",
            "36DF0AAFD8B8D7597CA10520D04B",
            4,
            "4BA30AB5E892B4E1649DD0928643",
            "ADCD46F5882E3747DEF36E956E97",
        );
        assert_parameters(
            &secp128r2(),
            "FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF",
            "D6031998D1B3BBFEBF59CC9BBFF9AEE1",
            "5EEEFCA380D02919DC2C6558BB6D8A5D",
            "3FFFFFFF7FFFFFFFBE0024720613B5A3",
            4,
            "7B6AA5D85E572983E6FB32A7CDEBC140",
            "27B6916A894D3AEE7106FE805FC34B44",
        );
        assert_parameters(
            &secp256k1(),
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
            "0",
            "7",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            1,
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
        );
        assert_parameters(
            &secp256r1(),
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
            "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
            1,
            "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
        );
    }

    #[allow(deprecated)]
    #[test]
    fn every_generic_fp_named_curve_has_the_declared_order_and_sec1_round_trips() {
        for pair in [secp112r1(), secp112r2(), secp128r2()] {
            assert_round_trips_and_order(pair.0, pair.1);
        }
        for pair in [
            secp112r1_dynamic(),
            secp112r2_dynamic(),
            secp128r2_dynamic(),
        ] {
            assert_round_trips_and_order(pair.0, pair.1);
        }
        for pair in [secp256k1(), secp256r1()] {
            assert_round_trips_and_order(pair.0, pair.1);
        }
        for pair in [secp256k1_dynamic(), secp256r1_dynamic()] {
            assert_round_trips_and_order(pair.0, pair.1);
        }
    }

    #[test]
    fn standard_scalar_multiplication_kats_match_rfc6979_and_bip340() {
        // RFC 6979 A.2.5 的 NIST P-256 key pair。
        let (_, p256_generator) = secp256r1();
        let p256 = p256_generator.mul_double_and_add(&hex(
            "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
        ));
        assert_eq!(
            p256.x().unwrap().to_big_uint(),
            hex("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6")
        );
        assert_eq!(
            p256.y().unwrap().to_big_uint(),
            hex("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299")
        );

        // BIP 340 test vector 0：secret key 3 的 x-only 公鑰。
        let (_, k1_generator) = secp256k1();
        let k1 = k1_generator.mul_double_and_add(&integer(3));
        assert_eq!(
            k1.x().unwrap().to_big_uint(),
            hex("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
        );
        assert!(!k1.y().unwrap().to_big_uint().test_bit(0));
    }

    fn decode_integer<B: FpInteger>(bytes: &[u8]) -> B {
        B::from_be_bytes(bytes).unwrap_or_else(|_| panic!("test scalar fits selected backend"))
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

    fn assert_coordinate_systems_match<B: FpInteger>(
        base: (Arc<FpCurve<B>>, FpPoint<B>),
        seed: u64,
    ) {
        let (base_curve, generator) = base;
        let mut state = seed;
        let point_scalar = decode_integer::<B>(&random_256_bits(&mut state));
        let scalar = decode_integer::<B>(&random_256_bits(&mut state));
        let random_point = generator.mul_double_and_add(&point_scalar).normalize();
        let x = random_point.x().unwrap().to_big_uint();
        let y = random_point.y().unwrap().to_big_uint();
        let mut expected = None;
        let mut expected_projective = None;

        for coordinate_system in [
            CoordinateSystem::Affine,
            CoordinateSystem::Homogeneous,
            CoordinateSystem::Jacobian,
            CoordinateSystem::JacobianModified,
        ] {
            let curve = Arc::new(
                (*base_curve)
                    .clone()
                    .with_coordinate_system(coordinate_system),
            );
            let point = curve.create_point(x.clone(), y.clone());
            let result = crate::scalar_mul::<FpCurve<B>>(&point, &scalar);
            assert!(result.is_valid());
            if let Some(expected) = &expected_projective {
                assert_eq!(&result, expected, "{coordinate_system:?}");
            } else {
                expected_projective = Some(result.clone());
            }
            let normalized = result.normalize();
            assert!(normalized.is_normalized());
            assert_eq!(normalized, point.mul_double_and_add(&scalar).normalize());
            let encoded = normalized.encode(false);
            if let Some(expected) = &expected {
                assert_eq!(&encoded, expected, "{coordinate_system:?}");
            } else {
                expected = Some(encoded);
            }
        }
    }

    #[test]
    fn all_fp_coordinate_systems_match_on_full_width_scalars() {
        assert_coordinate_systems_match(secp256k1(), 0x4B31_C00D_F00D_0001);
        assert_coordinate_systems_match(secp256r1(), 0x5231_C00D_F00D_0001);
    }
}
