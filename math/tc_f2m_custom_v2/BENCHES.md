# tc_f2m_custom_v2 benchmarks

## Purpose

This crate repeats tc_f2m_curve_v2's curves with the field fixed at compile
time, as BC's `SecT*` classes do, for speed alone. These numbers measure what
that buys over the generic curve on the same named curve.

## Results

Measured on 2026-10-22 on the local Windows x86-64 host, an 11th Gen Intel
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
| field `multiply` | 26.5 ns | 142.6 ns | 5.4× |
| field `square` | 30.7 ns | 138.9 ns | 4.5× |
| field `invert` | 3.31 µs | 6.91 µs | 2.1× |
| Ct point multiplication (ladder) | 90.5 µs | 444.1 µs | 4.9× |
| Var point multiplication (wNAF) | 73.0 µs | 421.2 µs | 5.8× |

On a Koblitz curve the Var curve multiplies by τNAF, as BC's custom curves
do. These pairs compare it with the plain wNAF on the same specialized curve.
Each scalar is one bit narrower than the order.

| Case | τNAF | wNAF | Ratio |
| --- | ---: | ---: | ---: |
| sect163k1 Var point multiplication | 114.8 µs | 72.6 µs | 0.63× |
| sect571k1 Var point multiplication | 1.17 ms | 2.22 ms | 1.89× |

## Reading

- This run was slower overall than the one on 2026-10-20. Even the
  specialized product went from 21.6 to 26.5 ns. Compare the ratios within
  this run, not absolute times across dates. On this host two runs of
  unchanged code differ by up to about 30%, far less than the gaps between
  the specialized and generic curves.
- The generic element sits on `PaddedBinPoly`, which allocates for every
  result. tc_binpoly's own benchmarks put a sect163 product on
  `FixedBinPoly`, without that allocation, near 47 ns. Roughly half the gap is
  the allocation. The rest is the written-out reduction and the three-limb
  CLMUL.
- `invert` is mostly its 162 squarings. They now share one product buffer
  across each `square_n`, as BC's `SquareN` keeps one, and wipe it once.
  In isolated runs that took the inversion from 3.19 to 2.96 µs.
- The point multiplications follow the field: about five times faster.
- τNAF replaces each doubling with a Frobenius map, which costs three
  squarings.
  - On sect571k1 it nearly halves the time.
  - On sect163k1 it is 1.6 times slower than the plain wNAF. Each call pays
    fixed costs that wNAF does not: the scalar's reduction modulo
    (τ^m − 1)/(τ − 1) on big integers, and a fresh table. A 163-bit
    multiplication is too short to win them back. Which cost dominates has
    not been measured.

## Reproducing

```text
cargo bench -p tc_f2m_custom_v2 --bench compare
```
