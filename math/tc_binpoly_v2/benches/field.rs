use core::hint::black_box;
use core::time::Duration;

use criterion::{BenchmarkId, Criterion};
use tc_binpoly_v2::{BinField, FixedBinPoly};

fn value<const N: usize>(field: BinField, seed: u64) -> FixedBinPoly<N> {
    let mut state = seed;
    let mut limbs = [0; N];
    for limb in &mut limbs {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *limb = state;
    }
    let top = field.n() & 63;
    if top != 0 {
        limbs[N - 1] &= (1 << top) - 1;
    }
    FixedBinPoly::from_limbs(field, limbs).unwrap()
}

fn field<const N: usize>(criterion: &mut Criterion, name: &str, field: BinField) {
    let x = value::<N>(field, 0x9E37_79B9_7F4A_7C15);
    let y = value::<N>(field, 0xD1B5_4A32_D192_ED03);

    let mut group = criterion.benchmark_group("multiply");
    group.bench_with_input(BenchmarkId::from_parameter(name), &(), |b, _| {
        b.iter(|| black_box(&x).multiply(black_box(&y)))
    });
    group.finish();

    let mut group = criterion.benchmark_group("square");
    group.bench_with_input(BenchmarkId::from_parameter(name), &(), |b, _| {
        b.iter(|| black_box(&x).square())
    });
    group.finish();

    let mut group = criterion.benchmark_group("invert");
    group.bench_with_input(BenchmarkId::from_parameter(name), &(), |b, _| {
        b.iter(|| black_box(&x).invert())
    });
    group.finish();
}

fn main() {
    let mut criterion = Criterion::default()
        .warm_up_time(Duration::from_secs(3))
        .measurement_time(Duration::from_secs(15))
        .configure_from_args();
    let c = &mut criterion;
    field::<2>(c, "sect113", BinField::trinomial(113, 9).unwrap());
    field::<3>(c, "sect163", BinField::pentanomial(163, 3, 6, 7).unwrap());
    field::<4>(c, "sect233", BinField::trinomial(233, 74).unwrap());
    field::<5>(c, "sect283", BinField::pentanomial(283, 5, 7, 12).unwrap());
    field::<7>(c, "sect409", BinField::trinomial(409, 87).unwrap());
    field::<9>(c, "sect571", BinField::pentanomial(571, 2, 5, 10).unwrap());
    criterion.final_summary();
}
