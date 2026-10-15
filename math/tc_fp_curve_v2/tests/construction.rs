use tc_bigint::PaddedBigUint;
use tc_fp_curve_v2::{FpCtCurve, FpError, FpField, FpVarCurve};

fn int(value: u8) -> PaddedBigUint {
    PaddedBigUint::from(value)
}

#[test]
fn an_even_modulus_is_refused() {
    assert_eq!(FpField::new(int(16)).err(), Some(FpError::EvenModulus));
    assert_eq!(FpField::new(int(0)).err(), Some(FpError::EvenModulus));
    assert!(FpField::new(int(17)).is_ok());
}

#[test]
fn a_coefficient_of_q_or_more_is_refused_by_both_curves() {
    let field = FpField::new(int(17)).unwrap();
    for (a, b) in [(17, 2), (2, 17), (255, 2)] {
        assert_eq!(
            FpVarCurve::new(&field, &int(a), &int(b), None, None).err(),
            Some(FpError::NotBelowModulus),
            "a = {a}, b = {b}"
        );
        assert_eq!(
            FpCtCurve::new(&field, &int(a), &int(b), None, None).err(),
            Some(FpError::NotBelowModulus),
            "a = {a}, b = {b}"
        );
    }
    assert!(FpVarCurve::new(&field, &int(16), &int(16), None, None).is_ok());
}

#[test]
fn a_coordinate_of_q_or_more_is_refused_by_both_curves() {
    let field = FpField::new(int(17)).unwrap();
    let var_curve = FpVarCurve::new(&field, &int(2), &int(2), None, None).unwrap();
    let ct_curve = FpCtCurve::new(&field, &int(2), &int(2), None, None).unwrap();
    for (x, y) in [(17, 1), (5, 17)] {
        assert_eq!(
            var_curve.create_point(&int(x), &int(y)).err(),
            Some(FpError::NotBelowModulus)
        );
        assert_eq!(
            ct_curve.create_point(&int(x), &int(y)).err(),
            Some(FpError::NotBelowModulus)
        );
    }
    assert!(var_curve.create_point(&int(5), &int(1)).is_ok());
    assert!(ct_curve.create_point(&int(5), &int(1)).is_ok());
}
