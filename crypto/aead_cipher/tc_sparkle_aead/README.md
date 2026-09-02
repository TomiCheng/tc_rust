# tc_sparkle_aead

`tc_sparkle_aead` implements the four SCHWAEMM authenticated-encryption
parameter sets built on the SPARKLE permutation. The implementation is
`no_std` and does not allocate.

## Variants

| Variant | Key | Nonce/rate | Tag | Permutation backend |
|---------|----:|-----------:|----:|---------------------|
| `Schwaemm128_128` | 16 bytes | 16 bytes | 16 bytes | Portable |
| `Schwaemm256_128` | 16 bytes | 32 bytes | 16 bytes | Portable |
| `Schwaemm192_192` | 24 bytes | 24 bytes | 24 bytes | Portable |
| `Schwaemm256_256` | 32 bytes | 32 bytes | 32 bytes | SSE2 `SparkleOpt16` or portable fallback |

On x86 and x86_64, SCHWAEMM256-256 asks `tc_runtime` for an SSE2 proof token
before entering the `#[target_feature(enable = "sse2")]` implementation. It
uses the portable permutation when SSE2 is unavailable or disabled. Other
architectures compile only the portable path.

## Parameters and use

`Params<'a>` is a convenience type that borrows its key, nonce, and initial
AAD. Callers may instead supply any type implementing `KeyParams`, `IvParams`,
and `InitialAadParams` from `tc_params`.

```rust
use tc_cipher::{AeadCipher, AeadCipherInit, CipherDirection};
use tc_sparkle_aead::{Engine, Params, Variant};

let key = [0_u8; 32];
let nonce = [1_u8; 32];
let params = Params::new(&key, &nonce, &[]);
let plaintext = b"message";

let mut cipher = Engine::new(Variant::Schwaemm256_256);
cipher.init(CipherDirection::Encrypt, &params)?;
cipher.process_aad_bytes(b"header")?;

let mut output = [0_u8; 7 + 32];
let mut written = cipher.process_bytes(plaintext, &mut output)?;
written += cipher.do_final(&mut output[written..])?;
assert_eq!(written, output.len());
# Ok::<(), Box<dyn std::error::Error>>(())
```

Associated data must be supplied before plaintext or ciphertext. During
decryption, `process_bytes()` may produce unauthenticated plaintext; callers
must not release or act on it until `do_final()` verifies the tag.

## Features

| Feature | Effect |
|---------|--------|
| `std` | Lets `tc_runtime` read runtime environment overrides. |
| `disable-x86-sse2` | Makes this crate use the portable permutation even when SSE2 is available. |

The default feature set is empty. With `std` enabled, setting
`TC_DISABLE_X86_SSE2` before the first feature-detection call also selects the
portable backend. The detection result is cached for the rest of the process.

## Benchmark

The Criterion benchmark measures SCHWAEMM256-256 encryption for 32-byte,
1-KiB, and 64-KiB messages. Engine initialization, output allocation, and
32-byte AAD processing occur outside the timed section; `process_bytes()` and
`do_final()` are timed. Reported throughput counts plaintext bytes and includes
the cost of producing the authentication tag.

Run the automatically selected SSE2 backend:

```bash
cargo bench -p tc_sparkle_aead --bench sparkle
```

Run the identical workload through the portable backend:

```bash
cargo bench -p tc_sparkle_aead --bench sparkle --features disable-x86-sse2
```

Results measured on 2026-09-02 with Rust 1.98.0 on the current Windows x86_64
development machine (`Intel64 Family 6 Model 140 Stepping 1`):

| Plaintext | SSE2 | Portable | SSE2 speedup |
|----------:|-----:|---------:|-------------:|
| 32 bytes | 86.24 MiB/s | 36.84 MiB/s | 2.34x |
| 1 KiB | 259.11 MiB/s | 109.81 MiB/s | 2.36x |
| 64 KiB | 306.37 MiB/s | 118.01 MiB/s | 2.60x |

These figures are a local measurement, not a performance guarantee. Criterion
reported central estimates of 353.88 ns versus 828.36 ns, 3.7690 us versus
8.8935 us, and 204.00 us versus 529.63 us respectively.

## Verification

Run the official SCHWAEMM vectors and the scalar/SSE2 equivalence test:

```bash
cargo test -p tc_sparkle_aead --locked
```

Verify the portable fallback and optimized release build separately:

```bash
cargo test -p tc_sparkle_aead --features disable-x86-sse2 --locked
cargo test -p tc_sparkle_aead --release --locked
```
