//! Baselines for the scalar kernel, reduction, multiplication, and inversion.
//!
//! Run with: `cargo bench -p tc_binpoly --bench baseline`

use std::hint::black_box;

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use tc_binpoly::scalar::impl_mul;
use tc_binpoly::{BinPolyInv, BinPolyMul, BinPolyMultiplier, ItohTsujii};

#[derive(Clone, Copy)]
enum Parameters {
    Trinomial(usize, usize),
    Pentanomial(usize, usize, usize, usize),
}

impl Parameters {
    fn n(self) -> usize {
        match self {
            Self::Trinomial(n, _) | Self::Pentanomial(n, ..) => n,
        }
    }

    fn label(self) -> String {
        match self {
            Self::Trinomial(n, k) => format!("tri-{n}-{k}"),
            Self::Pentanomial(n, k1, k2, k3) => format!("penta-{n}-{k1}-{k2}-{k3}"),
        }
    }

    fn multiplier(self) -> BinPolyMultiplier {
        match self {
            Self::Trinomial(n, k) => BinPolyMultiplier::trinomial(n, k).unwrap(),
            Self::Pentanomial(n, k1, k2, k3) => {
                BinPolyMultiplier::pentanomial(n, k1, k2, k3).unwrap()
            }
        }
    }
}

const PARAMETERS: [Parameters; 9] = [
    Parameters::Trinomial(113, 9),
    Parameters::Trinomial(193, 15),
    Parameters::Trinomial(233, 74),
    Parameters::Trinomial(239, 158),
    Parameters::Trinomial(409, 87),
    Parameters::Pentanomial(131, 2, 3, 8),
    Parameters::Pentanomial(163, 3, 6, 7),
    Parameters::Pentanomial(283, 5, 7, 12),
    Parameters::Pentanomial(571, 2, 5, 10),
];

fn inputs(multiplier: &BinPolyMultiplier) -> (Vec<u64>, Vec<u64>) {
    let mut x: Vec<_> = (0..multiplier.size())
        .map(|i| {
            0x9E37_79B9_7F4A_7C15_u64
                .wrapping_mul(i as u64 + 1)
                .rotate_left((i * 11) as u32)
        })
        .collect();
    let mut y: Vec<_> = (0..multiplier.size())
        .map(|i| {
            0xD1B5_4A32_D192_ED03_u64
                .wrapping_mul(i as u64 + 3)
                .rotate_right((i * 7) as u32)
        })
        .collect();
    if multiplier.n() & 63 != 0 {
        let mask = (1_u64 << (multiplier.n() & 63)) - 1;
        let last = multiplier.size() - 1;
        x[last] &= mask;
        y[last] &= mask;
    }
    (x, y)
}

fn bench_impl_mul(c: &mut Criterion) {
    let mut group = c.benchmark_group("binpoly/impl_mul");
    for parameters in PARAMETERS {
        let multiplier = parameters.multiplier();
        let (x, y) = inputs(&multiplier);
        let mut zz = vec![0_u64; multiplier.size() * 2];
        group.bench_function(BenchmarkId::new(parameters.label(), parameters.n()), |b| {
            b.iter(|| impl_mul(black_box(&x), black_box(&y), black_box(&mut zz)))
        });
    }
    group.finish();
}

fn bench_reduce(c: &mut Criterion) {
    let mut group = c.benchmark_group("binpoly/reduce");
    for parameters in PARAMETERS {
        let multiplier = parameters.multiplier();
        let (x, y) = inputs(&multiplier);
        let mut product = vec![0_u64; multiplier.size() * 2];
        impl_mul(&x, &y, &mut product);
        let mut z = vec![0_u64; multiplier.size()];
        group.bench_function(BenchmarkId::new(parameters.label(), parameters.n()), |b| {
            b.iter_batched(
                || product.clone(),
                |mut tt| multiplier.reduce_extended(black_box(&mut tt), black_box(&mut z)),
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn bench_multiply(c: &mut Criterion) {
    let mut group = c.benchmark_group("binpoly/multiply");
    for parameters in PARAMETERS {
        let multiplier = parameters.multiplier();
        let (x, y) = inputs(&multiplier);
        let mut z = vec![0_u64; multiplier.size()];
        group.bench_function(BenchmarkId::new(parameters.label(), parameters.n()), |b| {
            b.iter(|| multiplier.multiply(black_box(&x), black_box(&y), black_box(&mut z)))
        });
    }
    group.finish();
}

fn bench_invert(c: &mut Criterion) {
    let mut group = c.benchmark_group("binpoly/invert");
    for parameters in PARAMETERS {
        let multiplier = parameters.multiplier();
        let inverter = ItohTsujii::new(multiplier.clone()).unwrap();
        let (x, _) = inputs(&multiplier);
        let mut z = vec![0_u64; multiplier.size()];
        group.bench_function(BenchmarkId::new(parameters.label(), parameters.n()), |b| {
            b.iter(|| inverter.invert(black_box(&x), black_box(&mut z)))
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_impl_mul,
    bench_reduce,
    bench_multiply,
    bench_invert
);
criterion_main!(benches);
