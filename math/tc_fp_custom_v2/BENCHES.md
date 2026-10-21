# tc_fp_custom_v2 benchmarks

## Purpose

This crate repeats tc_fp_curve_v2's curves with the field fixed at compile
time, as BC's `SecP*` classes do. The only reason for that is speed. These
numbers show how much faster it is than the generic curve on the same named
curve.

## Results

Measured on 2026-10-22 on the local Windows x86-64 host, an 11th Gen Intel
Core i7-1185G7 at 3.00 GHz, using Rust 1.98.0 and Cargo's optimized bench
profile. Both sides of each pair follow the same contract. The Ct pair is
constant time, and both of its sides use the complete formulas with a 4-bit
fixed window. The Var pair is variable time, and both of its sides use wNAF
in Jacobian coordinates. These results describe this host, not a
cross-platform ranking.

Each case ran under Criterion with a 3-second warm-up and a 15-second
measurement window. The field operands are the P-256 generator's coordinates.
Each scalar is as wide as its curve's order.

| Case | Specialized | Generic | Ratio |
| --- | ---: | ---: | ---: |
| P-256 field `multiply` | 82.6 ns | 272.8 ns | 3.3× |
| P-256 field `square` | 79.2 ns | 270.8 ns | 3.4× |
| P-256 field `invert` | 3.50 µs | 3.90 µs | 1.11× |
| P-256 field `sqrt` | 21.5 µs | 73.4 µs | 3.4× |
| P-256 Ct point multiplication | 886.7 µs | 2.58 ms | 2.9× |
| P-256 Var point multiplication | 459.8 µs | 1.39 ms | 3.0× |
| P-384 Ct point multiplication | 3.30 ms | 4.28 ms | 1.30× |
| P-384 Var point multiplication | 1.71 ms | 2.38 ms | 1.39× |
| P-521 Ct point multiplication | 2.39 ms | 9.16 ms | 3.8× |
| P-521 Var point multiplication | 1.11 ms | 3.96 ms | 3.6× |

The Var curve multiplies by the GLV split on the k1 curves, where BC's custom
curves do. This pair compares it with the plain wNAF on the same specialized
secp256k1 curve, with a 256-bit scalar.

| Case | GLV | wNAF | Ratio |
| --- | ---: | ---: | ---: |
| secp256k1 Var point multiplication | 228.7 µs | 353.8 µs | 1.55× |

## Reading

- This run was slower overall than the one on 2026-10-21. The generic P-256
  product, whose code did not change, went from 200 to 273 ns. Compare the
  ratios within this run, not absolute times across dates. On this host two
  runs of unchanged code differ by up to about 30%.
- The fields follow BC and sit on 32-bit limbs, except P-521. tc_bigint's
  Montgomery form uses 64-bit words on this host.
  - At 256 bits, the Solinas reduction and the absence of allocation still
    win by about three times.
  - P-384 keeps 12 limbs with Nat384's Karatsuba step, and its lead is only
    1.3 to 1.4 times. It is now slower than P-521. Putting it on 64-bit limbs
    has not been tried.
  - P-521 now sits on nine 64-bit limbs instead of BC's seventeen 32-bit ones.
    Its point multiplications went from slightly slower than the generic
    curve to nearly four times faster. In isolated runs the Ct one went from
    5.89 to 1.80 ms.
- `square` was no faster than `multiply`, because the indexed loop of BC's
  `Nat.SquareWordAddTo` kept its bounds checks. Iterating slices removed them.
  In isolated runs P-256 squaring went from 80 to 62 ns, against 70 ns for a
  product. In this run the two come out closer.
- `sqrt` is mostly its 253 squarings. They now share one product buffer
  across each `square_n`, as BC's `SquareN` keeps one, and wipe it once. That
  moved the P-256 root within noise.
- `invert` is safegcd on both sides, so its small gain comes from the digit
  arithmetic alone.
- GLV splits the scalar in two halves of about 128 bits and runs them
  together, so it halves the doublings. That saves about a third of the time.

## Reproducing

```text
cargo bench -p tc_fp_custom_v2 --bench compare
```
