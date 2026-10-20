# tc_f2m_custom_v2 benchmarks

## Purpose

This crate repeats tc_f2m_curve_v2's curves with the field fixed at compile
time, as BC's `SecT*` classes do, for speed alone. These numbers measure what
that buys over the generic curve on the same named curve.

## Results

Measured on 2026-10-20 on the local Windows x86-64 host, an 11th Gen Intel
Core i7-1185G7 at 3.00 GHz, using Rust 1.98.0 and Cargo's optimized bench
profile. The CPU has PCLMULQDQ and BMI2, so both sides multiplied by CLMUL and
squared by PDEP; the two contracts match, the Ct pair constant time and the Var
pair variable time. These results describe this host, not a cross-platform
ranking.

Each case used Criterion with a 3-second warm-up and a 15-second measurement
window, on sect163r2. The field operands are the generator's coordinates; the
scalar has 162 bits. Both Var curves use lambda-projective coordinates.

| Case | Specialized | Generic | Ratio |
| --- | ---: | ---: | ---: |
| field `multiply` | 21.6 ns | 102.8 ns | 4.8× |
| field `square` | 19.4 ns | 106.8 ns | 5.5× |
| field `invert` | 3.27 µs | 4.42 µs | 1.35× |
| Ct point multiplication (ladder) | 60.8 µs | 254.6 µs | 4.2× |
| Var point multiplication (wNAF) | 49.1 µs | 241.3 µs | 4.9× |

## Reading

- The generic element sits on `PaddedBinPoly`, which allocates for every
  result. tc_binpoly_v2's own benchmarks put a sect163 product on
  `FixedBinPoly`, without that allocation, near 47 ns: roughly half the gap is
  the allocation, the rest the written-out reduction and the three-limb CLMUL.
- `invert` is dominated by its 162 squarings: 162 × 19.4 ns plus nine products
  comes to the measured 3.3 µs. The generic inversion runs its chain on limbs
  inside tc_binpoly_v2, free of the allocation, so it gains least here. Each
  specialized squaring still wipes its six-limb product; a chain that kept one
  buffer and wiped it once, as BC's `SquareN` keeps one, may save some of it,
  which is not measured.
- The point multiplications follow the field: four to five times faster.
- On this host two runs of unchanged code differ by up to about 20%, far less
  than these gaps.

## Reproducing

```text
cargo bench -p tc_f2m_custom_v2 --bench compare
```
