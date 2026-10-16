mod common;

use common::{B, GX, ONE, SYSTEMS, Var, bytes, generator, int, sect163r2};
use tc_ec_core_v2::algo::{
    AlgorithmError, clean_point, import_point, montgomery_trick, normalize_all, validate_point,
};
use tc_ec_core_v2::{CoordinateSystem, Curve, FieldElement, Point};
use tc_f2m_curve_v2::{F2mField, F2mFieldElement, F2mVarCurve, F2mVarPoint};

fn is_normalized(point: &F2mVarPoint<'_>) -> bool {
    point.projective_z().is_none_or(|z| z.is_one())
}

#[test]
fn import_point_moves_a_point_to_an_equivalent_curve_in_its_coordinate_system() {
    for from in SYSTEMS {
        let source = sect163r2(from);
        let p = <&F2mVarCurve as Curve>::multiply(&generator(&source), &int(5));
        for to in SYSTEMS {
            let target = sect163r2(to);
            let imported = import_point(&target, &p).unwrap();
            assert!(
                core::ptr::eq(imported.curve(), &target),
                "{from:?} -> {to:?}"
            );
            assert!(is_normalized(&imported), "{from:?} -> {to:?}");
            assert_eq!(
                (imported.x(), imported.y()),
                (p.x(), p.y()),
                "{from:?} -> {to:?}"
            );
            assert!(
                import_point(&target, &source.infinity())
                    .unwrap()
                    .is_infinity()
            );
        }
    }
}

#[test]
fn import_point_rejects_another_equation_or_another_field() {
    let source = sect163r2(CoordinateSystem::Affine);
    let p = generator(&source);
    let other_b = F2mVarCurve::new(common::field(), &bytes(ONE), &bytes(ONE), None, None).unwrap();
    let other_field = F2mVarCurve::new(
        F2mField::trinomial(163, 1).unwrap(),
        &bytes(ONE),
        &bytes(B),
        None,
        None,
    )
    .unwrap();
    assert_eq!(
        import_point(&other_b, &p).unwrap_err(),
        AlgorithmError::CurveMismatch
    );
    assert_eq!(
        import_point(&other_field, &p).unwrap_err(),
        AlgorithmError::CurveMismatch
    );
}

#[test]
fn validate_point_accepts_infinity_and_points_of_the_subgroup_only() {
    for system in SYSTEMS {
        let curve = sect163r2(system);
        let g = generator(&curve);
        assert!(validate_point(&g).is_ok());
        assert!(validate_point(&curve.infinity()).is_ok());

        // (0, √b) has order 2, so it and G plus it lie outside the subgroup of odd order.
        let handle = &curve;
        let root_b = Curve::b(&handle).sqrt().unwrap();
        let t = <Var<'_> as Curve>::create_point(&handle, Curve::zero(&handle), root_b);
        assert!(t.is_on_curve() && t.twice().is_infinity());
        assert_eq!(
            validate_point(&t).unwrap_err(),
            AlgorithmError::InvalidPoint
        );
        assert_eq!(
            validate_point(&g.add(&t)).unwrap_err(),
            AlgorithmError::InvalidPoint
        );

        let off_curve = curve.create_point(&bytes(GX), &bytes(GX)).unwrap();
        assert_eq!(
            validate_point(&off_curve).unwrap_err(),
            AlgorithmError::InvalidPoint
        );
    }
}

#[test]
fn clean_point_imports_then_validates() {
    let source = sect163r2(CoordinateSystem::LambdaProjective);
    let target = sect163r2(CoordinateSystem::Affine);
    let p = <&F2mVarCurve as Curve>::multiply(&generator(&source), &int(3));
    let cleaned = clean_point(&target, &p).unwrap();
    assert!(core::ptr::eq(cleaned.curve(), &target));
    assert_eq!((cleaned.x(), cleaned.y()), (p.x(), p.y()));

    let off_curve = source.create_point(&bytes(GX), &bytes(GX)).unwrap();
    assert_eq!(
        clean_point(&target, &off_curve).unwrap_err(),
        AlgorithmError::InvalidPoint
    );
    let other = F2mVarCurve::new(common::field(), &bytes(ONE), &bytes(ONE), None, None).unwrap();
    assert_eq!(
        clean_point(&other, &p).unwrap_err(),
        AlgorithmError::CurveMismatch
    );
}

fn xs(curve: &F2mVarCurve, count: u64) -> Vec<F2mFieldElement> {
    let g = generator(curve);
    (1..=count)
        .map(|k| <&F2mVarCurve as Curve>::multiply(&g, &int(k)).x().unwrap())
        .collect()
}

#[test]
fn montgomery_trick_inverts_a_batch_with_one_inversion_and_an_optional_scale() {
    let curve = sect163r2(CoordinateSystem::LambdaProjective);
    let values = xs(&curve, 9);

    let mut inverses = values.clone();
    montgomery_trick(&mut inverses, None).unwrap();
    for (value, inverse) in values.iter().zip(&inverses) {
        assert!(value.multiply(inverse).is_one());
    }

    let scale = values[4].clone();
    let mut scaled = values.clone();
    montgomery_trick(&mut scaled, Some(&scale)).unwrap();
    for (value, inverse) in values.iter().zip(&scaled) {
        assert!(value.multiply(&scale).multiply(inverse).is_one());
    }
}

#[test]
fn montgomery_trick_rejects_zero_and_leaves_the_input_unchanged() {
    let curve = sect163r2(CoordinateSystem::Affine);
    let mut values = xs(&curve, 4);
    values[2] = (&curve).zero();
    let before = values.clone();
    assert_eq!(
        montgomery_trick(&mut values, None),
        Err(AlgorithmError::NotInvertible)
    );
    assert!(values == before);
}

#[test]
fn normalize_all_scales_every_projective_point_to_z_one() {
    for system in SYSTEMS {
        let curve = sect163r2(system);
        let g = generator(&curve);
        let mut points: Vec<_> = (0..12)
            .map(|k| <&F2mVarCurve as Curve>::multiply(&g, &int(k)))
            .collect();
        let originals = points.clone();

        normalize_all(&mut points).unwrap();
        for (point, original) in points.iter().zip(&originals) {
            assert!(point == original, "{system:?}");
            assert!(is_normalized(point), "{system:?}");
        }
        assert!(points[0].is_infinity(), "{system:?}");
    }
}

#[test]
fn normalize_all_rejects_mixed_curves_before_touching_the_slice() {
    let curve = sect163r2(CoordinateSystem::LambdaProjective);
    let other = F2mVarCurve::new(common::field(), &bytes(ONE), &bytes(ONE), None, None)
        .unwrap()
        .with_coordinate_system(CoordinateSystem::LambdaProjective);
    let g = generator(&curve);
    let three = <&F2mVarCurve as Curve>::multiply(&g, &int(3));
    let mut points = vec![three.clone(), other.infinity(), three.twice()];
    let before: Vec<_> = points.iter().map(Point::projective_z).collect();

    assert_eq!(
        normalize_all(&mut points),
        Err(AlgorithmError::CurveMismatch)
    );
    let after: Vec<_> = points.iter().map(Point::projective_z).collect();
    assert!(before == after);
}
