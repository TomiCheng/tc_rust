# tc_fp_custom_v2 benchmarks

## Purpose

This crate repeats tc_fp_curve_v2's curves with the field fixed at compile
time, as BC's `SecP*` classes do. The only reason for that is speed. These
numbers show how much faster it is than the generic curve on the same named
curve, and what the fixed-base multipliers of `tc_ec_core_v2::multiplier`
buy on top.

## Results

Measured on 2026-10-22 on the local Windows x86-64 host, an 11th Gen Intel
Core i7-1185G7 at 3.00 GHz, using Rust 1.98.0 and Cargo's optimized bench
profile. The host ran on mains power with the IDE closed and no background
download. Both sides of each pair follow the same contract. The Ct pair is
constant time, and both of its sides use the complete formulas with a 4-bit
fixed window. The Var pair is variable time, and both of its sides use wNAF
in Jacobian coordinates. These results describe this host, not a
cross-platform ranking.

Each case ran under Criterion with a 3-second warm-up and a 15-second
measurement window. The field operands are the P-256 generator's coordinates.
Each scalar is as wide as its curve's order.

| Case | Specialized | Generic | Ratio |
| --- | ---: | ---: | ---: |
| P-256 field `multiply` | 77.8 ns | 168.8 ns | 2.2× |
| P-256 field `square` | 71.2 ns | 150.4 ns | 2.1× |
| P-256 field `invert` | 2.51 µs | 2.53 µs | 1.01× |
| P-256 field `sqrt` | 16.2 µs | 41.9 µs | 2.6× |
| P-256 Ct point multiplication | 527.8 µs | 1.51 ms | 2.9× |
| P-256 Var point multiplication | 260.2 µs | 835.4 µs | 3.2× |
| P-384 Ct point multiplication | 910.4 µs | 2.86 ms | 3.1× |
| P-384 Var point multiplication | 478.9 µs | 1.39 ms | 2.9× |
| P-521 Ct point multiplication | 1.72 ms | 5.57 ms | 3.2× |
| P-521 Var point multiplication | 747.5 µs | 2.50 ms | 3.3× |

The Var curve multiplies by the GLV split on the k1 curves, where BC's custom
curves do. This pair compares it with the plain wNAF on the same specialized
secp256k1 curve, with a 256-bit scalar.

| Case | GLV | wNAF | Ratio |
| --- | ---: | ---: | ---: |
| secp256k1 Var point multiplication | 149.4 µs | 240.1 µs | 1.61× |

### Fixed-base multipliers

Each multiplier is built once for the generator and then multiplies by the
same scalars as above, all on the specialized curves.

- *Per call* is `PerCall`, the curve's own `multiply`, which builds its table
  every time.
- *Kept table* is the curve's own method with its table built once
  (`SecPCtPrecomputed`, `SecPVarPrecomputed`).
- *Comb* is BC's fixed-point comb (`CombCt`, `CombVar`), with six rows.

| Case | Per call | Kept table | Comb | Comb ratio |
| --- | ---: | ---: | ---: | ---: |
| P-256 Ct | 526.9 µs | 500.5 µs | 216.2 µs | 2.4× |
| P-256 Var | 260.5 µs | 249.6 µs | 75.8 µs | 3.4× |
| secp256k1 Var (GLV) | 152.3 µs | 132.9 µs | 68.5 µs | 2.2× |

Building them costs this much, once per base:

| Case | Kept table | Comb |
| --- | ---: | ---: |
| P-256 Ct | 24.3 µs | 466.5 µs |
| P-256 Var | 16.2 µs | 270.0 µs |
| secp256k1 Var (GLV) | 17.8 µs | 255.1 µs |

## Reading

- This run replaces the two earlier ones of 2026-10-22. Those ran on battery
  under a background download that took about six cores, and came out 30% to
  four times slower. Compare ratios, not times, against older runs.
- The fields follow BC's algorithms. P-256 and the smaller fields sit on
  32-bit limbs. P-384 multiplies on 64-bit limbs and reduces on BC's 32-bit
  words. P-521 sits on 64-bit limbs throughout.
  - At 256 bits, the Solinas reduction and the absence of allocation win by
    about three times.
  - P-384 was only 1.3 to 1.4 times faster on 32-bit limbs with Nat384's
    Karatsuba step. Its 64-bit products bring it to three times.
  - P-521 was slightly slower than the generic curve on BC's seventeen
    limbs. Its nine 64-bit limbs bring it to three times as well.
- `square` is now faster than `multiply`. The indexed loop of BC's
  `Nat.SquareWordAddTo` used to keep its bounds checks. Iterating slices
  removed them.
- `sqrt` is mostly its 253 squarings, so it gains what squaring gains.
- `invert` is safegcd on both sides and comes out even.
- GLV splits the scalar into two halves of about 128 bits and runs them
  together, which halves the doublings.
- Of the fixed-base multipliers:
  - Keeping the curve's own table saves only the build, 4% to 13% of a
    multiplication.
  - The comb needs only 43 doublings and 43 additions at 256 bits, and runs
    2.2 to 3.4 times faster. The Ct comb still gains 2.4 times while it
    reads all 64 entries for every column.
  - A comb costs about one multiplication to build, so on P-256 it pays from
    the second use of the same base.
  - On secp256k1 the comb gains less, as GLV has already halved the
    doublings it removes, and it pays only from the fourth use.

## Reproducing

```text
cargo bench -p tc_fp_custom_v2 --bench compare
```
