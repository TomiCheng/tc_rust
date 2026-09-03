# tc_runtime

`tc_runtime` provides dependency-free, algorithm-independent runtime support
for the `tc_rust` workspace. It is `no_std` unless its optional `std` feature is
enabled.

The x86 API mirrors the capabilities currently queried by Bouncy Castle's
`Org.BouncyCastle.Runtime.Intrinsics.X86` namespace. Every capability provides:

```rust
use tc_runtime::intrinsics::x86::{Aes, Avx2, Sse2};

if let Some(sse2) = Sse2::detect() {
    // Pass the proof token to an SSE2 backend.
    let _ = sse2;
}

assert_eq!(Aes::detect().is_some(), Aes::is_enabled());
assert_eq!(Avx2::detect().is_some(), Avx2::is_enabled());
```

The private field in each proof token prevents safe caller code from creating
one without first performing detection.

## Capabilities

| Bouncy Castle capability | Rust capability | Detection |
| --- | --- | --- |
| `Aes` | `Aes` (`AesNi` alias) | CPUID AES-NI |
| `Avx2` | `Avx2` | CPUID AVX/AVX2 and OS XMM/YMM state |
| `Bmi1.X64` | `bmi1::X64` / `Bmi1X64` | 64-bit process and CPUID BMI1 |
| `Bmi2` | `Bmi2` | CPUID BMI2 |
| `Bmi2.X64` | `bmi2::X64` / `Bmi2X64` | 64-bit process and CPUID BMI2 |
| `Pclmulqdq` | `Pclmulqdq` | CPUID PCLMULQDQ |
| `Pclmulqdq.V256` | `pclmulqdq::V256` / `PclmulqdqV256` | PCLMULQDQ, VPCLMULQDQ and OS XMM/YMM state |
| `Pclmulqdq.V512` | `pclmulqdq::V512` / `PclmulqdqV512` | PCLMULQDQ, VPCLMULQDQ, AVX-512F and OS ZMM state |
| `Sse2` | `Sse2` | x86_64 baseline or CPUID SSE2 on x86 |
| `Sse41` | `Sse41` | CPUID SSE4.1 |
| `Ssse3` | `Ssse3` | CPUID SSSE3 |

The types remain available on non-x86 architectures, where `is_enabled()`
returns `false` and `detect()` returns `None`. AVX2 and the vector-width
PCLMULQDQ checks include operating-system extended-state support; a CPU feature
bit alone is not sufficient to execute those instructions safely.

## Disabling optimized backends

Each instruction-set backend can be disabled at compile time:

| Capability | Cargo feature | Runtime environment variable with `std` |
| --- | --- | --- |
| AES-NI | `disable-x86-aes-ni` | `TC_DISABLE_X86_AES_NI` |
| AVX2 | `disable-x86-avx2` | `TC_DISABLE_X86_AVX2` |
| BMI1 | `disable-x86-bmi1` | `TC_DISABLE_X86_BMI1` |
| BMI2 | `disable-x86-bmi2` | `TC_DISABLE_X86_BMI2` |
| PCLMULQDQ, all widths | `disable-x86-pclmulqdq` | `TC_DISABLE_X86_PCLMULQDQ` |
| PCLMULQDQ 256-bit only | `disable-x86-pclmulqdq-v256` | `TC_DISABLE_X86_PCLMULQDQ_V256` |
| PCLMULQDQ 512-bit only | `disable-x86-pclmulqdq-v512` | `TC_DISABLE_X86_PCLMULQDQ_V512` |
| SSE2 | `disable-x86-sse2` | `TC_DISABLE_X86_SSE2` |
| SSE4.1 | `disable-x86-sse41` | `TC_DISABLE_X86_SSE41` |
| SSSE3 | `disable-x86-ssse3` | `TC_DISABLE_X86_SSSE3` |

For example:

```text
cargo build --features tc_runtime/disable-x86-avx2
cargo build --features tc_runtime/disable-x86-pclmulqdq
```

Runtime environment variables are read only when the `std` feature is enabled:

```text
TC_DISABLE_X86_AVX2=1
TC_DISABLE_X86_PCLMULQDQ=1
```

The presence of a variable disables the matching capability regardless of its
value. Results are cached, so changing an environment variable after the first
check has no effect. The general PCLMULQDQ switch also disables its V256 and
V512 capabilities.

These switches prevent callers from selecting the matching optimized backend;
they do not guarantee that the Rust compiler emits no instructions belonging
to that instruction set. In particular, SSE2 is part of the x86_64 baseline.
