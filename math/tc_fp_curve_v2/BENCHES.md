# tc_fp_curve_v2 benchmarks

## Purpose

The constant-time curve is always the one for a secret, so these numbers do
not choose between the two sets for a private key or a nonce. They measure
what the variable-time set buys on public values, such as verifying a
signature, and so whether it is worth keeping.

## Results

Measured on 2026-10-14 on the local Windows x86-64 host, an 11th Gen Intel
Core i7-1185G7 at 3.00 GHz, using Rust 1.98.0 and Cargo's optimized bench
profile, so a limb is 64 bits. These results describe this host and run, not
a cross-platform ranking.

Each case used Criterion with a 3-second warm-up and a 15-second measurement
window. Values below are Criterion's central time estimates. The curve is
secp256r1; `k` and `u2` are 256 bits long and `u1` is 255.

**Field arithmetic, shared by both sets.**

| Operation | Time |
| --- | ---: |
| `multiply` | 150.6 ns |
| `square` | 149.2 ns |
| `invert` | 2.50 µs |

**`k * G`; lower is better.**

| Curve | Multiplier | Time |
| --- | --- | ---: |
| `FpCtCurve` | 4-bit fixed window | 1.49 ms |
| `FpVarCurve`, affine | wNAF | 840.5 µs |
| `FpVarCurve`, homogeneous | wNAF | 802.1 µs |
| `FpVarCurve`, Jacobian | wNAF | 796.6 µs |
| `FpVarCurve`, modified Jacobian | wNAF | 804.7 µs |
| `FpVarCurve`, affine | double-and-add | 1.43 ms |
| `FpVarCurve`, homogeneous | double-and-add | 1.05 ms |
| `FpVarCurve`, Jacobian | double-and-add | 998.0 µs |
| `FpVarCurve`, modified Jacobian | double-and-add | 905.5 µs |

**`u1 * G + u2 * Q`, the core of signature verification; lower is better.**

| Curve | Method | Time |
| --- | --- | ---: |
| `FpCtCurve` | two fixed-window multiplications and an addition | 2.86 ms |
| `FpVarCurve`, Jacobian | interleaved wNAF (`sum_of_two_multiplies`) | 959.2 µs |
| `FpVarCurve`, modified Jacobian | interleaved wNAF (`sum_of_two_multiplies`) | 903.1 µs |

## Reading

- A single multiplication is about 1.9 times faster by wNAF than in constant
  time; the coordinate system barely matters for wNAF.
- Verification is about 3.1 times faster. Part of that is the constant-time
  side computing the two products separately: an interleaved constant-time
  multi-scalar product, sharing one chain of doublings, would narrow it.
- `square` costs the same as `multiply`: the padded Montgomery form has no
  dedicated squaring.

## Reproducing

```text
cargo bench -p tc_fp_curve_v2 --bench ct_var
```
