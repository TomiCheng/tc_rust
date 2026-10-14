use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_core_v2::algo::AlgorithmError;
use tc_ec_core_v2::wnaf::{
    WNafTable, generate_compact_window_naf, generate_jsf, generate_naf, generate_window_naf,
    get_naf_weight, get_window_size, shamirs_trick, sum_of_multiplies, sum_of_two_multiplies,
    wnaf_mul, wnaf_mul_point,
};
use tc_ec_core_v2::{CoordinateSystem, Point};
use tc_fp_curve_v2::named_curves::SECP256R1;
use tc_fp_curve_v2::{FpField, FpVarCurve, FpVarPoint};

type Var<'a> = &'a FpVarCurve<'a>;

fn int(value: u64) -> PaddedBigUint {
    PaddedBigUint::from(value)
}

fn hex(text: &str) -> PaddedBigUint {
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect();
    <PaddedBigUint as ArrayEncoding<u8>>::from_be(&bytes).unwrap()
}

fn scalars() -> impl Iterator<Item = u64> {
    (0..600).chain([
        0x5555_5555_5555_5555,
        0xaaaa_aaaa_aaaa_aaaa,
        0x8000_0000_0000_0000,
        0x7fff_ffff_ffff_ffff,
        u64::MAX - 1,
        u64::MAX,
    ])
}

fn rebuild(digits: impl IntoIterator<Item = i32>) -> i128 {
    digits
        .into_iter()
        .enumerate()
        .map(|(i, digit)| i128::from(digit) << i)
        .sum()
}

// 256-bit scalars for the multiplications, with n - 1, n and n + 1 of secp256r1.
const LARGE: [&str; 5] = [
    "c51e4753afdec1e6b6c6a5b992f43f8dd0c7a8933072708b6522468b2ffb06fd",
    "0000000000000000000000000000000000000000000000000000000000000001",
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
];

#[test]
fn naf_digits_are_non_adjacent_and_rebuild_the_scalar() {
    for k in scalars() {
        let naf = generate_naf::<Var<'_>>(&int(k));
        assert!(naf.iter().all(|d| (-1..=1).contains(d)), "k = {k}");
        assert!(
            naf.windows(2).all(|pair| pair[0] == 0 || pair[1] == 0),
            "k = {k}"
        );
        assert_eq!(
            rebuild(naf.iter().map(|&d| i32::from(d))),
            i128::from(k),
            "k = {k}"
        );
        assert_eq!(
            get_naf_weight::<Var<'_>>(&int(k)),
            naf.iter().filter(|&&d| d != 0).count()
        );
    }
    assert!(generate_naf::<Var<'_>>(&int(0)).is_empty());
}

#[test]
fn window_naf_digits_are_odd_bounded_spaced_and_rebuild_the_scalar() {
    for width in 2..=8 {
        let bound = 1i32 << (width - 1);
        for k in scalars() {
            let naf = generate_window_naf::<Var<'_>>(width, &int(k));
            let nonzero: Vec<usize> = (0..naf.len()).filter(|&i| naf[i] != 0).collect();
            for &i in &nonzero {
                let digit = i32::from(naf[i]);
                assert!(
                    digit % 2 != 0 && digit.abs() < bound,
                    "w = {width}, k = {k}"
                );
            }
            assert!(
                nonzero.windows(2).all(|pair| pair[1] - pair[0] >= width),
                "w = {width}, k = {k}"
            );
            assert_eq!(
                rebuild(naf.iter().map(|&d| i32::from(d))),
                i128::from(k),
                "w = {width}, k = {k}"
            );
            assert!(naf.last().is_none_or(|&d| d != 0), "w = {width}, k = {k}");
        }
    }
}

#[test]
#[should_panic(expected = "wNAF width must be in the range 2..=8")]
fn window_naf_rejects_a_width_above_eight() {
    generate_window_naf::<Var<'_>>(9, &int(5));
}

#[test]
#[should_panic(expected = "wNAF width must be in the range 2..=8")]
fn window_naf_rejects_a_width_below_two() {
    generate_window_naf::<Var<'_>>(1, &int(5));
}

fn expand(compact: &[i32]) -> Vec<i32> {
    let mut dense = Vec::new();
    for &entry in compact {
        let zeros = (entry & 0xffff) as usize;
        dense.resize(dense.len() + zeros, 0);
        dense.push(entry >> 16);
    }
    dense
}

#[test]
fn compact_window_naf_expands_to_the_dense_one() {
    for width in 2..=16 {
        for k in scalars() {
            let dense = expand(&generate_compact_window_naf::<Var<'_>>(width, &int(k)));
            assert_eq!(
                rebuild(dense.iter().copied()),
                i128::from(k),
                "w = {width}, k = {k}"
            );
            if width <= 8 {
                let window = generate_window_naf::<Var<'_>>(width, &int(k));
                assert_eq!(
                    dense,
                    window.iter().map(|&d| i32::from(d)).collect::<Vec<_>>()
                );
            }
        }
    }
}

#[test]
#[should_panic(expected = "compact wNAF width must be in the range 2..=16")]
fn compact_window_naf_rejects_a_width_above_sixteen() {
    generate_compact_window_naf::<Var<'_>>(17, &int(5));
}

#[test]
fn jsf_rebuilds_both_scalars_with_a_zero_column_in_every_three() {
    let pairs = scalars().zip(scalars().skip(37)).chain([
        (u64::MAX, u64::MAX),
        (u64::MAX, 0),
        (1, u64::MAX),
    ]);
    for (a, b) in pairs {
        let jsf = generate_jsf::<Var<'_>>(&int(a), &int(b));
        assert!(
            jsf.iter().flatten().all(|d| (-1..=1).contains(d)),
            "{a}, {b}"
        );
        assert_eq!(
            rebuild(jsf.iter().map(|c| i32::from(c[0]))),
            i128::from(a),
            "{a}, {b}"
        );
        assert_eq!(
            rebuild(jsf.iter().map(|c| i32::from(c[1]))),
            i128::from(b),
            "{a}, {b}"
        );
        assert!(
            jsf.windows(3).all(|three| three.contains(&[0, 0])),
            "{a}, {b}"
        );
    }
    assert!(generate_jsf::<Var<'_>>(&int(0), &int(0)).is_empty());
}

#[test]
fn jsf_of_five_and_forty_two_is_the_one_of_solinas() {
    // BC's version gives [1, 0], [0, 1], [1, 0], [0, 1], [0, 0], [0, 1]: five nonzero
    // columns, three of them in a row.
    assert_eq!(
        generate_jsf::<Var<'_>>(&int(5), &int(42)),
        [[-1, 0], [-1, 1], [0, 0], [1, 1], [0, 0], [0, 1]]
    );
}

#[test]
fn window_size_follows_the_bc_thresholds() {
    for (bits, width) in [
        (0, 2),
        (12, 2),
        (13, 3),
        (40, 3),
        (41, 4),
        (120, 4),
        (121, 5),
        (256, 5),
        (337, 6),
        (896, 6),
        (897, 7),
        (2304, 7),
        (2305, 8),
        (usize::MAX, 8),
    ] {
        assert_eq!(get_window_size(bits), width, "bits = {bits}");
    }
}

#[test]
fn a_table_holds_the_odd_multiples_and_their_negations() {
    let field = FpField::new(int(17));
    let curve = FpVarCurve::new(&field, &int(2), &int(2), Some(int(19)), Some(int(1)))
        .with_coordinate_system(CoordinateSystem::Jacobian);
    let g = curve.create_point(&int(5), &int(1));
    for width in 2..=6 {
        let table = WNafTable::new(&g, width, true);
        assert_eq!(table.width(), width);
        assert_eq!(table.precomputed().len(), 1 << (width - 2));
        let negated = table.precomputed_negated().unwrap();
        for (i, (point, negation)) in table.precomputed().iter().zip(negated).enumerate() {
            let odd = g.multiply(&int(2 * i as u64 + 1));
            assert!(
                *point == odd && *negation == odd.negate(),
                "w = {width}, i = {i}"
            );
            assert!(point.is_normalized(), "w = {width}, i = {i}");
        }
        assert!(
            WNafTable::new(&g, width, false)
                .precomputed_negated()
                .is_none()
        );
    }
}

#[test]
#[should_panic(expected = "wNAF table width must be in the range 2..=16")]
fn a_table_rejects_a_width_below_two() {
    let field = FpField::new(int(17));
    let curve = FpVarCurve::new(&field, &int(2), &int(2), None, None);
    WNafTable::new(&curve.create_point(&int(5), &int(1)), 1, true);
}

#[test]
fn wnaf_multiplication_matches_double_and_add_for_every_width() {
    let field = SECP256R1.field();
    for system in [CoordinateSystem::Affine, CoordinateSystem::JacobianModified] {
        let curve = SECP256R1.var_curve(&field).with_coordinate_system(system);
        let g = SECP256R1.var_generator(&curve);
        for width in 2..=8 {
            for negated in [false, true] {
                let table = WNafTable::new(&g, width, negated);
                for k in LARGE
                    .iter()
                    .map(|k| hex(k))
                    .chain([int(0), int(2), int(255)])
                {
                    assert!(
                        wnaf_mul::<Var<'_>>(&table, &k) == g.multiply(&k),
                        "{system:?}, w = {width}"
                    );
                }
            }
        }
        for k in LARGE.iter().map(|k| hex(k)) {
            assert!(
                wnaf_mul_point::<Var<'_>>(&g, &k) == g.multiply(&k),
                "{system:?}"
            );
        }
        assert!(wnaf_mul_point::<Var<'_>>(&g, &hex(LARGE[3])).is_infinity());
    }
}

#[test]
fn wnaf_multiplication_runs_on_the_constant_time_points_as_well() {
    let field = SECP256R1.field();
    let curve = SECP256R1.ct_curve(&field);
    let g = SECP256R1.ct_generator(&curve);
    for k in LARGE.iter().map(|k| hex(k)) {
        assert!(wnaf_mul_point::<&tc_fp_curve_v2::FpCtCurve<'_>>(&g, &k) == g.multiply(&k));
    }
}

fn secp256r1_points<'a>(curve: &'a FpVarCurve<'a>) -> (FpVarPoint<'a>, FpVarPoint<'a>) {
    let g = SECP256R1.var_generator(curve);
    let q = g.multiply(&hex(LARGE[0]));
    (g, q)
}

#[test]
fn shamir_and_the_sums_match_separate_multiplications() {
    let field = SECP256R1.field();
    let curve = SECP256R1
        .var_curve(&field)
        .with_coordinate_system(CoordinateSystem::Jacobian);
    let (g, q) = secp256r1_points(&curve);
    let ks: Vec<PaddedBigUint> = LARGE
        .iter()
        .map(|k| hex(k))
        .chain([int(0), int(1)])
        .collect();
    for a in &ks {
        for b in &ks {
            let expected = g.multiply(a).add(&q.multiply(b));
            assert!(shamirs_trick::<Var<'_>>(&g, a, &q, b).unwrap() == expected);
            assert!(sum_of_two_multiplies::<Var<'_>>(&g, a, &q, b).unwrap() == expected);
        }
    }

    let points: Vec<_> = (1..5).map(|i| g.multiply(&int(i * 1000 + 7))).collect();
    let scalars: Vec<_> = LARGE.iter().take(4).map(|k| hex(k)).collect();
    let expected = points
        .iter()
        .zip(&scalars)
        .fold(curve.infinity(), |sum, (p, k)| sum.add(&p.multiply(k)));
    assert!(sum_of_multiplies::<Var<'_>>(&points, &scalars).unwrap() == expected);
    assert!(
        sum_of_multiplies::<Var<'_>>(&points[..1], &scalars[..1]).unwrap()
            == points[0].multiply(&scalars[0])
    );
}

#[test]
fn the_sums_reject_mismatched_lengths_curves_and_invalid_points() {
    let field = SECP256R1.field();
    let curve = SECP256R1.var_curve(&field);
    let (g, q) = secp256r1_points(&curve);
    let k = hex(LARGE[0]);
    let empty: [FpVarPoint<'_>; 0] = [];
    assert_eq!(
        sum_of_multiplies::<Var<'_>>(&empty, &[]).unwrap_err(),
        AlgorithmError::InvalidLength
    );
    assert_eq!(
        sum_of_multiplies::<Var<'_>>(&[g.clone(), q.clone()], core::slice::from_ref(&k))
            .unwrap_err(),
        AlgorithmError::InvalidLength
    );

    let off_curve = curve.create_point(&hex(LARGE[0]), &hex(LARGE[1]));
    assert_eq!(
        sum_of_two_multiplies::<Var<'_>>(&g, &k, &off_curve, &k).unwrap_err(),
        AlgorithmError::InvalidPoint
    );
    assert_eq!(
        shamirs_trick::<Var<'_>>(&off_curve, &k, &g, &k).unwrap_err(),
        AlgorithmError::InvalidPoint
    );

    let elsewhere = FpVarCurve::new(&field, &int(1), &int(1), None, None);
    let stranger = elsewhere.infinity();
    assert_eq!(
        shamirs_trick::<Var<'_>>(&g, &k, &stranger, &k).unwrap_err(),
        AlgorithmError::CurveMismatch
    );
    assert_eq!(
        sum_of_multiplies::<Var<'_>>(&[g.clone(), stranger], &[k.clone(), k]).unwrap_err(),
        AlgorithmError::CurveMismatch
    );
}
