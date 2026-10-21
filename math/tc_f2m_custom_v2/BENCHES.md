# tc_f2m_custom_v2 benchmarks

## Purpose

This crate repeats tc_f2m_curve_v2's curves with the field fixed at compile
time, as BC's `SecT*` classes do, for speed alone. These numbers measure what
that buys over the generic curve on the same named curve, and what the
fixed-base multipliers of `tc_ec_core_v2::multiplier` buy on top.

## Results

Measured on 2026-10-22 on the local Windows x86-64 host, an 11th Gen Intel
Core i7-1185G7 at 3.00 GHz, using Rust 1.98.0 and Cargo's optimized bench
profile. The host ran on mains power with the IDE closed and no background
download. The CPU has PCLMULQDQ and BMI2, so both sides multiplied by CLMUL and
squared by PDEP. The two contracts match: the Ct pair is constant time and the
Var pair variable time. These results describe this host, not a
cross-platform ranking.

Each case used Criterion with a 3-second warm-up and a 15-second measurement
window, on sect163r2. The field operands are the generator's coordinates; the
scalar has 162 bits. Both Var curves use lambda-projective coordinates.

| Case | Specialized | Generic | Ratio |
| --- | ---: | ---: | ---: |
| field `multiply` | 20.7 ns | 98.0 ns | 4.7× |
| field `square` | 21.3 ns | 162.1 ns | 7.6× |
| field `invert` | 2.51 µs | 6.61 µs | 2.6× |
| Ct point multiplication (ladder) | 90.7 µs | 473.5 µs | 5.2× |
| Var point multiplication (wNAF) | 84.0 µs | 478.6 µs | 5.7× |

On a Koblitz curve the Var curve multiplies by τNAF, as BC's custom curves
do. These pairs compare it with the plain wNAF on the same specialized curve.
Each scalar is one bit narrower than the order.

| Case | τNAF | wNAF | Ratio |
| --- | ---: | ---: | ---: |
| sect163k1 Var point multiplication | 128.4 µs | 88.0 µs | 0.69× |
| sect571k1 Var point multiplication | 1.20 ms | 2.23 ms | 1.86× |

### Fixed-base multipliers

Each multiplier is built once for the generator of the same Koblitz curves and
then multiplies by the same scalars.

- *Per call* is `PerCall`, the curve's own τNAF, which builds its table every
  time.
- *Kept table* is the same τNAF with its table built once
  (`SecTVarPrecomputed`).
- *Comb* is BC's fixed-point comb (`CombVar`): five rows on sect163k1, six on
  sect571k1.

| Case | Per call | Kept table | Comb | Comb ratio |
| --- | ---: | ---: | ---: | ---: |
| sect163k1 Var | 128.4 µs | 82.5 µs | 21.2 µs | 6.0× |
| sect571k1 Var | 994.7 µs | 848.3 µs | 535.8 µs | 1.86× |

Building them costs this much, once per base:

| Case | Kept table | Comb |
| --- | ---: | ---: |
| sect163k1 Var | 43.5 µs | 75.9 µs |
| sect571k1 Var | 201.9 µs | 1.78 ms |

## Reading

- This run replaces the earlier one of 2026-10-22. That one ran on battery
  under a background download that took about six cores. Compare ratios, not
  times, against older runs.
- In this run the per-call sect571k1 multiplication measured 1.20 ms in one
  group and 0.99 ms in another. Treat differences under about 20% as noise.
- The generic element sits on `PaddedBinPoly`, which allocates for every
  result. tc_binpoly's own benchmarks put a sect163 product on
  `FixedBinPoly`, without that allocation, near 47 ns. Roughly half the gap is
  the allocation. The rest is the written-out reduction and the three-limb
  CLMUL.
- `invert` is mostly its 162 squarings. They share one product buffer across
  each `square_n`, as BC's `SquareN` keeps one.
- The point multiplications follow the field: five to six times faster.
- τNAF replaces each doubling with a Frobenius map, which costs three
  squarings.
  - On sect571k1 it nearly halves the time.
  - On sect163k1 the per-call τNAF is 1.5 times slower than wNAF. The kept
    table shows why: building it, with the reduction it carries, takes 43 µs
    of the 128 µs. Kept, τNAF takes 82.5 µs and edges out wNAF's 88.0 µs.
- Of the fixed-base multipliers:
  - The comb gains six times on sect163k1 and pays even when used once:
    building it and multiplying take 97 µs, against 128 µs per call.
  - On sect571k1 it gains 1.86 times but costs about 1.8 multiplications to
    build, so it pays from the fourth use.

## Reproducing

```text
cargo bench -p tc_f2m_custom_v2 --bench compare
```
