//! 本次 F2m 拆分使用的兩條 SEC 2 具名曲線。
//!
//! sect163k1 覆蓋五項式約簡，sect233k1 覆蓋三項式約簡。無後綴版本採用
//! 固定 `FixedBinaryPoly + U256` 表示，`_dynamic` 版本使用配置式
//! `BinaryPoly + BigUint`，兩者共用參數。

use alloc::sync::Arc;

use tc_bigint::{BigUint, U256};
use tc_binpoly::{BinaryPoly, FixedBinaryPoly};

use crate::{F2mCurve, F2mInteger, F2mPoint, F2mPolynomial};

/// 固定寬度的 SEC 2 sect163k1 與基點。
pub fn sect163k1() -> (
    Arc<F2mCurve<FixedBinaryPoly<3>, U256>>,
    F2mPoint<FixedBinaryPoly<3>, U256>,
) {
    sect163k1_with()
}

/// 配置式的 SEC 2 sect163k1 與基點。
pub fn sect163k1_dynamic() -> (
    Arc<F2mCurve<BinaryPoly, BigUint>>,
    F2mPoint<BinaryPoly, BigUint>,
) {
    sect163k1_with()
}

/// 以指定多項式表示建立 SEC 2 sect163k1。
pub fn sect163k1_with<P: F2mPolynomial, B: F2mInteger>() -> (Arc<F2mCurve<P, B>>, F2mPoint<P, B>) {
    let curve = Arc::new(
        F2mCurve::pentanomial(
            163,
            3,
            6,
            7,
            integer(1),
            integer(1),
            Some(hex("04000000000000000000020108A2E0CC0D99F8A5EF")),
            Some(integer(2)),
        )
        .expect("sect163k1 parameters are valid"),
    );
    let point = curve.create_point(
        hex("02FE13C0537BBC11ACAA07D793DE4E6D5E5C94EEE8"),
        hex("0289070FB05D38FF58321F2E800536D538CCDAA3D9"),
    );
    (curve, point)
}

/// 固定寬度的 SEC 2 sect233k1 與基點。
pub fn sect233k1() -> (
    Arc<F2mCurve<FixedBinaryPoly<4>, U256>>,
    F2mPoint<FixedBinaryPoly<4>, U256>,
) {
    sect233k1_with()
}

/// 配置式的 SEC 2 sect233k1 與基點。
pub fn sect233k1_dynamic() -> (
    Arc<F2mCurve<BinaryPoly, BigUint>>,
    F2mPoint<BinaryPoly, BigUint>,
) {
    sect233k1_with()
}

/// 以指定多項式表示建立 SEC 2 sect233k1。
pub fn sect233k1_with<P: F2mPolynomial, B: F2mInteger>() -> (Arc<F2mCurve<P, B>>, F2mPoint<P, B>) {
    let curve = Arc::new(
        F2mCurve::trinomial(
            233,
            74,
            integer(0),
            integer(1),
            Some(hex(
                "8000000000000000000000000000069D5BB915BCD46EFB1AD5F173ABDF",
            )),
            Some(integer(4)),
        )
        .expect("sect233k1 parameters are valid"),
    );
    let point = curve.create_point(
        hex("017232BA853A7E731AF129F22FF4149563A419C26BF50A4C9D6EEFAD6126"),
        hex("01DB537DECE819B7F70F555A67C427A8CD9BF18AEB9B56E0C11056FAE6A3"),
    );
    (curve, point)
}

pub(crate) fn hex<B: F2mInteger>(value: &str) -> B {
    assert!(
        value.len() <= 64,
        "named-curve constants must be at most 256 bits"
    );
    let mut bytes = [0_u8; 32];
    let byte_length = value.len().div_ceil(2);
    let start = bytes.len() - byte_length;
    let mut source = 0;
    let mut target = start;
    if value.len() & 1 != 0 {
        bytes[target] = hex_digit(value.as_bytes()[0]);
        source = 1;
        target += 1;
    }
    while source < value.len() {
        let high = hex_digit(value.as_bytes()[source]);
        let low = hex_digit(value.as_bytes()[source + 1]);
        bytes[target] = high << 4 | low;
        source += 2;
        target += 1;
    }
    match B::from_unsigned_be_bytes(&bytes[start..]) {
        Ok(value) => value,
        Err(_) => panic!("named-curve constant does not fit the selected integer type"),
    }
}

fn integer<B: F2mInteger>(value: u8) -> B {
    match B::from_unsigned_be_bytes(&[value]) {
        Ok(value) => value,
        Err(_) => panic!("small named-curve constant fits the selected integer type"),
    }
}

fn hex_digit(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("named-curve constant is valid hexadecimal"),
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;
    use tc_bigint_old::BigInt;

    fn assert_matches_old<P: F2mPolynomial, B: F2mInteger>(
        new_curve: &(Arc<F2mCurve<P, B>>, F2mPoint<P, B>),
        old_curve: &(Arc<tc_ec::F2mCurve>, tc_ec::F2mPoint),
        bits: usize,
        seed: u64,
    ) {
        let (new_curve, new_g) = new_curve;
        let (_, old_g) = old_curve;
        assert!(new_g.is_valid());
        assert_eq!(new_g.encode(false), old_g.encode(false));
        assert_eq!(new_g.twice().encode(false), old_g.twice().encode(false));
        assert_eq!(
            (&new_g.twice() + new_g).encode(false),
            (&old_g.twice() + old_g).encode(false)
        );

        // 兩份可重現的滿寬隨機純量：第一份先產生隨機有效點，第二份再從該點
        // 做純量乘。這同時覆蓋非基點輸入與最高位，不只測低 8 bits。
        let mut state = seed;
        let point_scalar_bytes = random_bits(bits, &mut state);
        let scalar_bytes = random_bits(bits, &mut state);
        let point_scalar = decode_test_integer::<B>(&point_scalar_bytes);
        let scalar = decode_test_integer::<B>(&scalar_bytes);
        assert_eq!(point_scalar.bit_length(), bits);
        assert_eq!(scalar.bit_length(), bits);

        let old_point_scalar = BigInt::from_bytes_be_unsigned(&point_scalar_bytes);
        let old_scalar = BigInt::from_bytes_be_unsigned(&scalar_bytes);
        let new_point = new_g.mul_double_and_add(&point_scalar);
        let old_point = old_g.mul_double_and_add(&old_point_scalar);
        assert_eq!(new_point.encode(false), old_point.encode(false));

        let new_result = new_point.mul_double_and_add(&scalar);
        let old_result = old_point.mul_double_and_add(&old_scalar);
        assert_eq!(new_result.encode(false), old_result.encode(false));

        for compressed in [false, true] {
            assert_eq!(
                new_curve
                    .decode_point(&new_result.encode(compressed))
                    .unwrap(),
                new_result
            );
        }
    }

    fn decode_test_integer<B: F2mInteger>(bytes: &[u8]) -> B {
        match B::from_unsigned_be_bytes(bytes) {
            Ok(value) => value,
            Err(_) => panic!("oracle scalar fits the selected integer type"),
        }
    }

    fn random_bits(bits: usize, state: &mut u64) -> Vec<u8> {
        let mut bytes = vec![0_u8; bits.div_ceil(8)];
        for chunk in bytes.chunks_mut(8) {
            *state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let word = state.to_be_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        let high_bits = bits & 7;
        if high_bits == 0 {
            bytes[0] |= 0x80;
        } else {
            bytes[0] &= (1_u8 << high_bits) - 1;
            bytes[0] |= 1_u8 << (high_bits - 1);
        }
        bytes
    }

    #[test]
    fn fixed_and_dynamic_curves_match_the_old_oracle() {
        let old_163 = tc_ec::ec::named_curves::sect163k1();
        let old_233 = tc_ec::ec::named_curves::sect233k1();

        assert_matches_old(&sect163k1(), &old_163, 163, 0x1630_F2C0_0000_0001);
        assert_matches_old(&sect163k1_dynamic(), &old_163, 163, 0x1630_F2C0_0000_0001);
        assert_matches_old(&sect233k1(), &old_233, 233, 0x2330_F2C0_0000_0001);
        assert_matches_old(&sect233k1_dynamic(), &old_233, 233, 0x2330_F2C0_0000_0001);
    }

    #[test]
    fn both_polynomial_backends_use_the_same_named_vectors() {
        assert_eq!(
            sect163k1().1.encode(false),
            sect163k1_dynamic().1.encode(false)
        );
        assert_eq!(
            sect233k1().1.encode(false),
            sect233k1_dynamic().1.encode(false)
        );
    }
}
