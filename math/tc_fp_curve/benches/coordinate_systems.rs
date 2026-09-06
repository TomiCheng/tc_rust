use core::hint::black_box;
use core::time::Duration;
use std::format;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use tc_bigint::U256;
use tc_fp_curve::named_curves::secp256k1;
use tc_fp_curve::{CoordinateSystem, FpPoint, inversion_count, reset_inversion_count};

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

fn bench_coordinate_systems(criterion: &mut Criterion) {
    let scalar = scalar();
    let mut group = criterion.benchmark_group("fp_scalar_mul_256");

    for coordinate_system in COORDINATE_SYSTEMS {
        let point = configured_point(coordinate_system);
        reset_inversion_count();
        let result = point.mul_double_and_add(&scalar).normalize();
        black_box(result);
        let inversions = inversion_count();
        if coordinate_system == CoordinateSystem::Affine {
            assert!(
                inversions > 300,
                "affine path unexpectedly avoided inversions"
            );
        } else {
            assert_eq!(inversions, 1, "projective path must normalize exactly once");
        }

        group.bench_with_input(
            BenchmarkId::new(
                "mul_and_normalize",
                format!("{coordinate_system:?}/inversions={inversions}"),
            ),
            &point,
            |bencher, point| {
                bencher
                    .iter(|| black_box(point.mul_double_and_add(black_box(&scalar)).normalize()));
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
    targets = bench_coordinate_systems
}
criterion_main!(benches);
