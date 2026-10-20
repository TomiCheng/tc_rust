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
  20 to 30% at small sizes would sit at the edge of that noise. The table above
  predates them; see below.
- `square` is cheaper than `multiply` at every size, as it should be: it only
  interleaves zeros before the reduction.
- `invert` is dominated by its n − 1 squarings: the Itoh–Tsujii chain adds only
  a handful of multiplications, nine for sect163.

## The size kernels

BC's `Size1` to `Size10` are now ported as one module, the x86 multiplier
taking them for 1 to 10 limbs, which covers every SEC field. Each is checked
against a bit-by-bit schoolbook product. Whether they are faster on this host
is not settled:

- A first try with only the three-limb kernel, alternated with the general one
  on 2026-10-20, put sect163 at 36.3 / 43.0 ns against 60.4 / 58.0 ns.
- With all ten, `multiply` ran in the order new, old, new the same day:

| Field | Limbs | New | Old | New again |
| --- | ---: | ---: | ---: | ---: |
| sect113 | 2 | 40.1 ns | 37.3 ns | 41.0 ns |
| sect163 | 3 | 63.6 ns | 50.9 ns | 47.7 ns |
| sect233 | 4 | 61.8 ns | 58.4 ns | 53.3 ns |
| sect283 | 5 | 82.8 ns | 73.2 ns | 70.0 ns |
| sect409 | 7 | 93.4 ns | 93.2 ns | 89.1 ns |
| sect571 | 9 | 163.8 ns | 142.1 ns | 122.8 ns |

The two runs of the same new code differ by up to a third, more than the gap
they are meant to show, so this run says nothing either way. Whether the
general dispatch over ten sizes costs what the single three-limb kernel saved
is also open. Settling it needs the two kernels timed interleaved in one
binary, or instruction counts, as under Valgrind, rather than wall time.

## Reproducing

```text
cargo bench -p tc_binpoly_v2 --bench field
```
