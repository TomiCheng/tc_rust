# tc_binpoly_v2 benchmarks

## Purpose

BC's x86 backend has hand-written kernels for products of 1 to 10 limbs
(`Size1` to `Size10`); this crate uses its general even and odd kernels at
every size below the Karatsuba cutoff instead. These numbers are the baseline
for deciding whether those kernels are worth porting.

## Results

Measured on 2026-10-16 on the local Windows x86-64 host, an 11th Gen Intel
Core i7-1185G7 at 3.00 GHz, using Rust 1.98.0 and Cargo's optimized bench
profile. The CPU has PCLMULQDQ and BMI2, so `multiply` ran the x86 medium
multiplier and `square` the PDEP expansion. These results describe this host,
not a cross-platform ranking.

Each case used Criterion with a 3-second warm-up and a 15-second measurement
window, through `FixedBinPoly`. The whole suite ran twice on unchanged code;
both central estimates are given.

| Field | Limbs | `multiply` | `square` | `invert` |
| --- | ---: | ---: | ---: | ---: |
| sect113 | 2 | 32.9 / 30.2 ns | 30.5 / 28.8 ns | 2.39 / 2.24 µs |
| sect163 | 3 | 47.0 / 46.8 ns | 40.6 / 39.5 ns | 4.76 / 4.29 µs |
| sect233 | 4 | 54.8 / 53.3 ns | 48.8 / 50.3 ns | 7.79 / 7.66 µs |
| sect283 | 5 | 80.3 / 65.4 ns | 53.1 / 54.3 ns | 9.98 / 12.0 µs |
| sect409 | 7 | 90.2 / 87.3 ns | 60.4 / 64.6 ns | 15.6 / 18.2 µs |
| sect571 | 9 | 121.5 / 129.0 ns | 74.7 / 86.0 ns | 28.6 / 30.5 µs |

## Reading

- The two runs differ by up to about 20% with nothing changed, so on this host
  a change must beat that to be told from noise. Compare by alternating the
  two builds in one sitting, more than once each.
- The specialized kernels mainly save a few PCLMULQDQ per product; a gain of
  20 to 30% at small sizes would sit at the edge of that noise. They are not
  ported for now.
- `square` is cheaper than `multiply` at every size, as it should be: it only
  interleaves zeros before the reduction.
- `invert` is dominated by its n − 1 squarings: the Itoh–Tsujii chain adds only
  a handful of multiplications, nine for sect163.

## Reproducing

```text
cargo bench -p tc_binpoly_v2 --bench field
```
