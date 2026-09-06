use tc_bigint::{ArrayEncoding, BigInt, U256};
use tc_ec_core::*;
use tc_fp_custom::*;

#[test]
fn jsf_reconstructs_full_width_without_overflow() {
    for (a, b) in [
        (U256::MAX, U256::MAX),
        (U256::MAX, U256::from(2_u8)),
        (U256::from(0_u8), U256::from(0_u8)),
    ] {
        let digits = generate_jsf::<SecP256K1Curve>(&a, &b);
        let mut actual = [BigInt::from(0_u8), BigInt::from(0_u8)];
        for pair in digits.iter().rev() {
            for i in 0..2 {
                actual[i] = (&actual[i] << 1) + BigInt::from(pair[i]);
            }
        }
        assert_eq!(
            actual,
            [a, b].map(|v| BigInt::from_unsigned_le_bytes(&v.to_le_bytes()))
        );
    }
    for a in 0..64_u32 {
        for b in 0..64_u32 {
            let mut actual = [0_i64; 2];
            for (bit, pair) in generate_jsf::<SecP256K1Curve>(&U256::from(a), &U256::from(b))
                .iter()
                .enumerate()
            {
                for i in 0..2 {
                    actual[i] += (pair[i] as i64) << bit;
                }
            }
            assert_eq!(actual, [a as i64, b as i64]);
        }
    }
}

fn public_algorithms<C: Curve<Scalar = U256>>(p: C::Point) {
    let q = p.double();
    for (a, b) in [(0, 0), (1, 1), (3, 19), (255, 17)] {
        let a = U256::from(a as u32);
        let b = U256::from(b as u32);
        let expected = scalar_mul::<C>(&p, &a).add(&scalar_mul::<C>(&q, &b));
        assert!(sum_of_two_multiplies::<C>(&p, &a, &q, &b).unwrap() == expected);
        assert!(shamirs_trick::<C>(&p, &a, &q, &b).unwrap() == expected);
        assert!(
            sum_of_multiplies::<C>(&[p.clone(), q.clone(), p.negate()], &[a, b, a]).unwrap()
                == scalar_mul::<C>(&q, &b)
        );
        assert!(FixedPointTable::new(&p, 256, 4).multiply(&a).unwrap() == scalar_mul::<C>(&p, &a));
    }
}

#[test]
fn public_algorithms_match_reference_fp_and_f2m() {
    public_algorithms::<SecP256K1Curve>(secp256k1().1);
    public_algorithms::<tc_f2m_custom::SecT163K1Curve>(tc_f2m_custom::sect163k1().1);
    assert!(matches!(
        sum_of_multiplies::<SecP256K1Curve>(&[], &[]),
        Err(AlgorithmError::InvalidLength)
    ));
}

fn secret_algorithms<C: SecretCurve<Scalar = U256>>(p: C::Point)
where
    C::Field: SecretField,
{
    for bytes in [[0_u8; 32], [255_u8; 32], {
        let mut b = [0; 32];
        b[0] = 19;
        b
    }] {
        let expected = scalar_mul::<C>(&p, &U256::from_le_bytes(&bytes).unwrap());
        let actual = multiply_secret::<C>(&p, &bytes).unwrap();
        assert!(actual.reveal() == expected);
    }
    let table = ECLookupTable::<C>::new(&[p.identity(), p.clone(), p.double()]).unwrap();
    assert!(table.lookup(1).reveal() == p);
    assert!(table.lookup(99).is_identity().unwrap_u8() == 1);
    let s = SecretPoint::<C>::from_public(&p).unwrap();
    assert_eq!(
        s.double()
            .ct_eq(&SecretPoint::from_public(&p.double()).unwrap())
            .unwrap_u8(),
        1
    );
    assert!(s.add(&s).reveal() == p.double());
    assert!(
        s.add(&SecretPoint::from_public(&p.negate()).unwrap())
            .is_identity()
            .unwrap_u8()
            == 1
    );
    assert!(
        sum_of_two_multiplies_secret::<C>(&p, &[7], &p.negate(), &[7])
            .unwrap()
            .is_identity()
            .unwrap_u8()
            == 1
    );
}

#[test]
fn import_clean_and_validation_enforce_curve_boundaries() {
    use std::sync::Arc;
    use tc_fp_curve::{FpCurve, FpPoint};
    let (curve, p) = tc_fp_curve::named_curves::secp256k1();
    let (_, other) = tc_fp_curve::named_curves::secp256r1();
    assert!(matches!(
        import_point(&curve, &other),
        Err(AlgorithmError::CurveMismatch)
    ));
    assert!(matches!(
        sum_of_two_multiplies::<FpCurve<U256>>(&p, &U256::from(1_u8), &other, &U256::from(1_u8)),
        Err(AlgorithmError::CurveMismatch)
    ));
    let target = Arc::new(
        (*curve)
            .clone()
            .with_coordinate_system(CoordinateSystem::Jacobian),
    );
    let imported = clean_point(&target, &p).unwrap();
    assert!(Arc::ptr_eq(imported.curve(), &target));
    assert_eq!(imported.encode(false), p.encode(false));
    let invalid = FpPoint::new(curve.clone(), curve.zero(), curve.zero());
    assert!(matches!(
        validate_point(&invalid),
        Err(AlgorithmError::InvalidPoint)
    ));
    assert!(matches!(
        clean_point(&curve, &invalid),
        Err(AlgorithmError::InvalidPoint)
    ));
    assert!(validate_point(&curve.identity()).is_ok());
    let mut batch = [p.clone(), other];
    let before = batch.clone();
    assert_eq!(
        normalize_all(&mut batch),
        Err(AlgorithmError::CurveMismatch)
    );
    assert_eq!(batch, before);
    assert!(matches!(
        FixedPointTable::new(&p, 1, 2).multiply(&U256::from(2_u8)),
        Err(AlgorithmError::ScalarTooLarge)
    ));
}

#[test]
fn secret_algorithms_match_reference_fp_and_f2m() {
    secret_algorithms::<SecP256K1Curve>(secp256k1().1);
    secret_algorithms::<SecP256R1Curve>(secp256r1().1);
    secret_algorithms::<tc_fp_curve::FpCurve<U256>>(tc_fp_curve::named_curves::secp256k1().1);
    secret_algorithms::<tc_f2m_custom::SecT163K1Curve>(tc_f2m_custom::sect163k1().1);
}

#[test]
fn batch_inverse_scale_and_atomic_failure() {
    let (curve, p) = secp256k1();
    let values = [p.x().unwrap(), p.y().unwrap(), curve.one()];
    let scale = p.x().unwrap();
    let mut batch = values;
    montgomery_trick(&mut batch, Some(&scale)).unwrap();
    for (a, b) in values.iter().zip(batch) {
        assert!(a.mul(&scale).mul(&b).is_one());
    }
    let mut bad = [values[0], curve.zero()];
    let before = bad;
    assert_eq!(
        montgomery_trick(&mut bad, None),
        Err(AlgorithmError::NotInvertible)
    );
    assert_eq!(bad, before);
    montgomery_trick::<SecP256K1FieldElement>(&mut [], None).unwrap();
}

#[test]
fn sm2_and_glv_match_independent_multiplication() {
    let (c, p) = sm2p256v1();
    assert!(p.is_valid());
    assert!(scalar_mul::<Sm2P256V1Curve>(&p, c.order()).is_identity());
    let (_, p) = secp256k1();
    for a in [U256::MAX, U256::from(0_u8), U256::from(1987_u32)] {
        assert_eq!(
            glv_mul::<SecP256K1Curve, _>(&p, &a, &SecP256K1Glv).unwrap(),
            scalar_mul::<SecP256K1Curve>(&p, &a)
        );
    }
}
