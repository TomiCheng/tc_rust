use tc_ec_core::*;
use tc_f2m_custom::*;
use tc_fp_custom::*;

fn check<C: SecretCurve>(p: C::Point)
where
    C::Field: SecretField,
{
    let mut expected = p.identity();
    for _ in 0..19 {
        expected = expected.add(&p);
    }
    assert!(multiply_secret::<C>(&p, &[19, 0]).unwrap().reveal() == expected);
    let order = p.curve().order().unwrap();
    let mut bytes = vec![0_u8; C::scalar_bit_length(order).div_ceil(8)];
    for bit in 0..C::scalar_bit_length(order) {
        if C::scalar_test_bit(order, bit) {
            bytes[bit / 8] |= 1 << (bit % 8);
        }
    }
    assert_eq!(
        multiply_secret::<C>(&p, &bytes)
            .unwrap()
            .is_identity()
            .unwrap_u8(),
        1
    );
    let mut points = [p.identity(), p.clone(), p.double(), expected];
    let normalized = points.clone().map(|p| p.normalize());
    normalize_all(&mut points).unwrap();
    for (a, b) in points.iter().zip(normalized) {
        assert!(*a == b);
        assert!(a.projective_z().is_none_or(|z| z.is_one()));
    }
    let zero = p.curve().a().ct_zero();
    let one = zero.ct_one();
    assert_eq!(zero.ct_invert().ct_eq(&zero).unwrap_u8(), 1);
    let value = p.x().unwrap();
    assert_eq!(value.ct_mul(&value.ct_invert()).ct_eq(&one).unwrap_u8(), 1);
}
// Separate modules avoid test-function/constructor name collisions.
mod prime {
    use super::*;
    macro_rules! named_prime {($($name:ident:$curve:ty),*)=>{$(
        #[test] fn $name(){check::<$curve>(tc_fp_custom::$name().1);}
    )*};}
    named_prime!(secp128r1:SecP128R1Curve,secp160k1:SecP160K1Curve,secp160r1:SecP160R1Curve,secp160r2:SecP160R2Curve,secp192k1:SecP192K1Curve,secp192r1:SecP192R1Curve,secp224k1:SecP224K1Curve,secp224r1:SecP224R1Curve,secp256k1:SecP256K1Curve,secp256r1:SecP256R1Curve,secp384r1:SecP384R1Curve,secp521r1:SecP521R1Curve,sm2p256v1:Sm2P256V1Curve);
}
mod binary {
    use super::*;
    macro_rules! named_binary {($($name:ident:$curve:ty),*)=>{$(
        #[test] fn $name(){check::<$curve>(tc_f2m_custom::$name().1);}
    )*};}
    named_binary!(sect113r1:SecT113R1Curve,sect113r2:SecT113R2Curve,sect131r1:SecT131R1Curve,sect131r2:SecT131R2Curve,sect163k1:SecT163K1Curve,sect163r1:SecT163R1Curve,sect163r2:SecT163R2Curve,sect193r1:SecT193R1Curve,sect193r2:SecT193R2Curve,sect233k1:SecT233K1Curve,sect233r1:SecT233R1Curve,sect239k1:SecT239K1Curve,sect283k1:SecT283K1Curve,sect283r1:SecT283R1Curve,sect409k1:SecT409K1Curve,sect409r1:SecT409R1Curve,sect571k1:SecT571K1Curve,sect571r1:SecT571R1Curve);
}
