# tc_runtime

`tc_runtime` provides low-level, algorithm-independent runtime support for the
`tc_rust` workspace. It is a `no_std` crate with no dependencies.

The initial API exposes CPU-feature detection through a path similar to
Bouncy Castle's runtime intrinsics namespace:

```rust
use tc_runtime::intrinsics::x86::Sse2;

if Sse2::is_enabled() {
    // An x86 SSE2 backend may be selected.
} else {
    // Use the portable backend.
}
```

`Sse2::is_enabled()` returns `true` on x86_64, detects CPUID leaf 1 EDX bit 26
on 32-bit x86, and returns `false` on non-x86 architectures.

AES-NI is detected independently through CPUID leaf 1 ECX bit 25:

```rust
use tc_runtime::intrinsics::x86::AesNi;

if AesNi::is_enabled() {
    // An AES-NI backend may be selected.
}
```

`AesNi::is_enabled()` detects only AES-NI; a backend that also requires SSE2
must check both capabilities. It returns `false` on non-x86 architectures.

Runtime CPUID results and runtime overrides are cached with `core` atomics.
Calls after the first detection only read the cached value.

## Disabling an optimized backend

An instruction-set backend can be disabled at compile time with a Cargo
feature:

```text
cargo build --features tc_runtime/disable-x86-sse2
cargo build --features tc_runtime/disable-x86-aes-ni
```

For applications that enable `tc_runtime`'s `std` feature, it can instead be
disabled at runtime by setting an environment variable before the first
detection call:

```text
TC_DISABLE_X86_SSE2=1
TC_DISABLE_X86_AES_NI=1
```

The presence of the variable disables the matching backend, regardless of its
value. Changing it after the first call has no effect because the result is
cached. Without the `std` feature, environment variables are not read and the
crate remains `no_std`.

These switches make `is_enabled()` return `false` and `detect()` return
`None`. They prevent callers from selecting the matching optimized backend;
they do not guarantee that the Rust compiler emits no instructions from that
instruction set. In particular, SSE2 is part of the x86_64 architecture
baseline.

Code that needs evidence of runtime support can retain a token instead:

```rust
use tc_runtime::intrinsics::x86::Sse2;

if let Some(sse2) = Sse2::detect() {
    // Pass `sse2` to a backend whose safety contract requires SSE2 support.
    let _ = sse2;
}
```
