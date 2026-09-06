use core::hint::black_box;
use core::time::Duration;
use std::format;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use tc_bigint::U256;
use tc_fp_curve::named_curves::secp256k1;
use tc_fp_curve::{
    CoordinateSystem, FpCurve, FpPoint, WNafTable, generate_compact_window_naf, scalar_mul,
    wnaf_mul,
};

const WINDOW_WIDTH: usize = 5;
const COORDINATE_SYSTEMS: [CoordinateSystem; 4] = [
    CoordinateSystem::Affine,
    CoordinateSystem::Homogeneous,
    CoordinateSystem::Jacobian,
    CoordinateSystem::JacobianModified,
];

fn configured_point(coordinate_system: CoordinateSystem) -> FpPoint<U256> {
    let (curve, generator) = secp256k1();
    let x = generator.x().unwrap().to_big_uint();
    let y = generator.y().unwrap().to_big_uint();
    let curve = std::sync::Arc::new((*curve).clone().with_coordinate_system(coordinate_system));
    curve.create_point(x, y)
}

fn scalar() -> U256 {
    U256::from_str_radix(
        "C51F7A94D308C624B1E975A06D42F89C357E1ABCDA75398F02468ACE13579BDF",
        16,
    )
    .unwrap()
}

fn bench_wnaf(criterion: &mut Criterion) {
    let scalar = scalar();
    let double_and_add_additions = scalar.bit_count();
    let wnaf_digits = generate_compact_window_naf::<FpCurve<U256>>(WINDOW_WIDTH, &scalar).len();
    let mut group = criterion.benchmark_group("fp_scalar_mul_wnaf_256");

    for coordinate_system in COORDINATE_SYSTEMS {
        let point = configured_point(coordinate_system);
        let table = WNafTable::new(&point, WINDOW_WIDTH, true);
        assert_eq!(
            scalar_mul::<FpCurve<U256>>(&point, &scalar),
            wnaf_mul::<FpCurve<U256>>(&table, &scalar)
        );

        group.bench_with_input(
            BenchmarkId::new(
                format!("{coordinate_system:?}/double_and_add"),
                format!("additions={double_and_add_additions}"),
            ),
            &point,
            |bencher, point| {
                bencher.iter(|| {
                    black_box(scalar_mul::<FpCurve<U256>>(
                        black_box(point),
                        black_box(&scalar),
                    ))
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new(
                format!("{coordinate_system:?}/wnaf_w{WINDOW_WIDTH}"),
                format!("nonzero_digits={wnaf_digits}"),
            ),
            &table,
            |bencher, table| {
                bencher.iter(|| {
                    black_box(wnaf_mul::<FpCurve<U256>>(
                        black_box(table),
                        black_box(&scalar),
                    ))
                });
            },
        );
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(2));
    targets = bench_wnaf
}
criterion_main!(benches);
