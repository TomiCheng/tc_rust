# tc_fp_custom_v2 benchmarks

## Purpose

This crate repeats tc_fp_curve_v2's curves with the field fixed at compile
time, as BC's `SecP*` classes do. The only reason for that is speed. These
numbers show how much faster it is than the generic curve on the same named
curve.

## Results

Measured on 2026-10-21 on the local Windows x86-64 host, an 11th Gen Intel
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
| P-256 field `multiply` | 83.0 ns | 200.2 ns | 2.4× |
| P-256 field `square` | 85.1 ns | 194.1 ns | 2.3× |
| P-256 field `invert` | 2.75 µs | 3.03 µs | 1.10× |
| P-256 Ct point multiplication | 573.6 µs | 1.64 ms | 2.9× |
| P-256 Var point multiplication | 295.5 µs | 869.7 µs | 2.9× |
| P-384 Ct point multiplication | 2.31 ms | 3.30 ms | 1.43× |
| P-384 Var point multiplication | 1.27 ms | 1.65 ms | 1.31× |
| P-521 Ct point multiplication | 6.24 ms | 5.78 ms | 0.93× |
| P-521 Var point multiplication | 2.44 ms | 2.55 ms | 1.04× |

## Reading

- The fields follow BC and sit on 32-bit limbs, while tc_bigint's Montgomery
  form uses 64-bit words on this host. Each generic word product therefore
  covers four times the bits of a specialized one.
  - At 256 bits, the Solinas reduction and the absence of allocation still
    win by nearly three times.
  - The lead shrinks as the field grows.
  - On P-521 the 17 limbs, even with Nat512's Karatsuba step, cost about as
    much as the generic 9-word Montgomery product. The Ct multiplication there
    is slightly slower than the generic one.
  - 64-bit limbs would change this, but they would leave BC's layout. That
    has not been tried.
- `square` is no faster than `multiply`. BC's `Nat256.Square` is written out
  word by word, and the generic loop of `nat::square` does not get that
  benefit.
- `invert` is safegcd on both sides, so its small gain comes from the digit
  arithmetic alone.
- The point multiplications follow the field products.

## Reproducing

```text
cargo bench -p tc_fp_custom_v2 --bench compare
```
