# RFC 7748 SIMD measurements

Measured on an Intel Core i7-1185G7 Windows x86-64 host, 2026-09-06, release builds
with rustc 1.98.0 (LLVM 22.1.8),
Criterion 0.8.2, 20 samples, one-second warmup and measurement per benchmark.
These short local measurements guide dispatch decisions, not universal speedups.

| Operation | x86 dispatch (AVX2 available) | Scalar, no default features |
| --- | ---: | ---: |
| X448 field multiply | 272 ns | 462 ns |
| X448 scalar multiply | 1.97 ms | 2.43 ms |
| X448 fixed base | 1.94 ms | 2.46 ms |
| X25519 scalar multiply | 123 us | 120 us |
| X25519 fixed base | 38.6 us | 40.3 us |
| X25519 field add/sub pair | 15.7 ns | 16.5 ns |

The new X448 AVX2 convolution improves the field multiply by about 41% and the
full ladder by about 19% in this run. It computes four unsigned 28-bit products
per vector instruction and accumulates at most 16 terms per coefficient, below
2^60. Reduction reuses the scalar field's fixed-schedule reducer. Differential
tests compare AVX2 with scalar multiplication at boundaries and random inputs.

X25519 retains its existing AVX2/SSE2 add/subtract paths. The end-to-end comparison
is mixed and does not support a broader X25519 SIMD speedup claim. No multiplier
rewrite is inferred from the add/subtract microbenchmark.

Reproduce the comparison sequentially, without other builds or benchmarks:

```text
cargo bench -p tc_rfc7748 --bench rfc7748 --locked -- --warm-up-time 1 --measurement-time 1 --sample-size 20 --save-baseline ec-roadmap-x86
cargo bench -p tc_rfc7748 --bench rfc7748 --no-default-features --locked -- --warm-up-time 1 --measurement-time 1 --sample-size 20 --baseline ec-roadmap-x86
```

The second run's reported positive change means the scalar build is slower
than the first (x86) baseline. Earlier stored Criterion baselines are not used
to attribute regressions: host load and prior builds can differ.
