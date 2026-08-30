# tc_block_cipher

## 1. Overview

`tc_block_cipher` provides pure-Rust block cipher implementations ported from
the Bouncy Castle C# engine package. All engines implement the `BlockCipher`
and `BlockCipherInit` traits from `tc_cipher_core` and use the crate's shared
`BlockCipherError` type.

Each algorithm has an owned parameter type, such as `AesParams` or
`ThreefishParams`. Parameter constructors validate key lengths and other
algorithm-specific settings before an engine is initialized. Parameter types
do not implement `Clone`, and their `Debug` implementations redact key and
tweak bytes.

The default `std` feature enables runtime AES-NI detection for `AesEngine` on
supported x86 and x86-64 processors. Disabling default features builds every
algorithm as `no_std` without allocating, and selects portable implementations.
The crate has no `alloc` feature: nothing in it allocates.

> This crate is a learning port and has not received an independent security
> audit. Do not use it as a replacement for an audited cryptographic library.

## 2. Usage

Add both the implementation crate and the trait crate to the application:

```toml
[dependencies]
tc_cipher_core = { path = "../tc_cipher_core" }
tc_block_cipher = { path = "../tc_block_cipher" }
```

Import `BlockCipherInit` to initialize an engine and `BlockCipher` to inspect
or process it. `CipherDirection` explicitly selects encryption or decryption:

```rust
use tc_block_cipher::{AES_BLOCK_BYTES, AesEngine, AesParams, BlockCipherError};
use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};

fn main() -> Result<(), BlockCipherError> {
    let key = [0x11u8; 16];
    let params = AesParams::new(&key)?;
    let plaintext = [0x22u8; AES_BLOCK_BYTES];

    let mut cipher = AesEngine::new();
    cipher.init(CipherDirection::Encrypt, &params)?;

    let mut ciphertext = [0u8; AES_BLOCK_BYTES];
    let written = cipher.process_block(&plaintext, &mut ciphertext)?;
    assert_eq!(written, AES_BLOCK_BYTES);

    cipher.init(CipherDirection::Decrypt, &params)?;

    let mut recovered = [0u8; AES_BLOCK_BYTES];
    cipher.process_block(&ciphertext, &mut recovered)?;
    assert_eq!(recovered, plaintext);

    Ok(())
}
```

`process_block` processes one block from the beginning of each slice. Both
slices must contain at least `block_size()` bytes. Calling it before `init`,
using an invalid parameter value, or supplying a short buffer returns a
`BlockCipherError`.

Most engines use `Engine::new()` plus `Params::new(key)`. The principal
exceptions are:

- `Dstu7624Engine::<BLOCK_WORDS, KEY_WORDS>::new()` takes both sizes as
  compile-time counts of 64-bit words, with the key equal to the block or twice
  it. Only the standard's five combinations are implemented, so an unsupported
  pairing will not compile. `Dstu7624Params::<KEY_WORDS>::new(key)` matches.
- `RijndaelEngine::<BLOCK_COLUMNS, KEY_COLUMNS>::new()` takes both sizes as
  compile-time counts of 32-bit columns, each in `4..=8`, so 128 through 256
  bits in 32-bit steps. `RijndaelParams::<KEY_COLUMNS>::new(key)` matches. As
  with Threefish, fixing the sizes at compile time avoids maximum-size storage
  on small `no_std` targets.
- `Threefish256Params`, `Threefish512Params`, and `Threefish1024Params` accept
  the matching key size plus an optional 16-byte tweak. Their corresponding
  engine types fix the block size at compile time, avoiding maximum-size
  storage on small `no_std` targets.
- `Rc2Params::with_effective_key_bits` sets the RC2 effective key size.
- `Rc532Engine::<ROUNDS>` and `Rc564Engine::<ROUNDS>` take the round count as a
  const parameter defaulting to the standard twelve, so the key schedule is
  sized at compile time. A type alias does not apply its default to a bare
  `new()`, so either name the count (`Rc532Engine::<16>::new()`) or annotate the
  binding (`let cipher: Rc532Engine = Rc532Engine::new();`).
- `Gost28147Params` can select a named or validated custom S-box.

## 3. Implemented algorithms

The crate currently exports 30 engine types. All implementations are covered
by known-answer tests; selected algorithms also include specification or Monte
Carlo vectors. Every algorithm is available in every build mode.

`core-only` needs neither an allocator nor `std`. Only AES gains an additional
`std` backend; an algorithm's API is the same across build modes.

| Family | Public engine types | Key and block support | Runtime |
|--------|---------------------|-----------------------|---------|
| AES | `AesEngine`, `AesLightEngine` | 128-bit block; 128/192/256-bit keys | core-only; `std`: AES-NI |
| ARIA | `AriaEngine` | 128-bit block; 128/192/256-bit keys | core-only |
| Blowfish | `BlowfishEngine` | 64-bit block; 32-448-bit keys | core-only |
| Camellia | `CamelliaEngine`, `CamelliaLightEngine` | 128-bit block; 128/192/256-bit keys | core-only |
| CAST | `Cast5Engine`, `Cast6Engine` | CAST5: 64-bit block, 40-128-bit keys; CAST6: 128-bit block, 128-256-bit keys in 32-bit steps | core-only |
| DES / Triple DES | `DesEngine`, `DesEdeEngine` | 64-bit block; 8-byte DES or 16/24-byte EDE keys | core-only |
| DSTU 7624 (Kalyna) | `Dstu7624Engine<BLOCK_WORDS, KEY_WORDS>` | 128/256/512-bit blocks; same-size or double-size keys where defined | core-only |
| GOST 28147-89 | `Gost28147Engine` | 64-bit block; 256-bit key; named and custom S-boxes | core-only |
| IDEA | `IdeaEngine` | 64-bit block; 128-bit key | core-only |
| Noekeon | `NoekeonEngine` | 128-bit block and key | core-only |
| RC2 | `Rc2Engine` | 64-bit block; variable key and effective key size | core-only |
| RC5 | `Rc532Engine<ROUNDS>`, `Rc564Engine<ROUNDS>` | 32- or 64-bit words; variable key, round count in the type | core-only |
| RC6 | `Rc6Engine` | 128-bit block; 1-255-byte key; 20 rounds | core-only |
| Rijndael | `RijndaelEngine<BLOCK_COLUMNS, KEY_COLUMNS>` | 128/160/192/224/256-bit blocks and keys, in any combination | core-only |
| SEED | `SeedEngine` | 128-bit block and key | core-only |
| Serpent / Tnepres | `SerpentEngine`, `TnepresEngine` | 128-bit block; 4-32-byte keys in 4-byte steps | core-only |
| SKIPJACK | `SkipjackEngine` | 64-bit block; 80-bit key | core-only |
| SM4 | `Sm4Engine` | 128-bit block and key | core-only |
| TEA / XTEA | `TeaEngine`, `XteaEngine` | 64-bit block; 128-bit key | core-only |
| Threefish | `Threefish256Engine`, `Threefish512Engine`, `Threefish1024Engine` | 256/512/1024-bit block and matching key; optional 128-bit tweak | core-only |
| Twofish | `TwofishEngine` | 128-bit block; 128/192/256-bit keys | core-only |

DES, Triple DES, Blowfish, IDEA, RC2, RC5, SKIPJACK, TEA, XTEA, and other
older designs are provided for compatibility and study, not as recommendations
for new protocols.

## 4. AES performance

AES has three execution strategies:

- `AesEngine` uses AES-NI when the default `std` feature is enabled and the
  x86/x86-64 processor reports AES and SSE2 support.
- The same `AesEngine` uses a portable T-table implementation on unsupported
  processors and in `no_std` builds.
- `AesLightEngine` uses a smaller table-based portable implementation when
  static table footprint matters more than throughput.

The following Criterion point estimates were measured on 2026-08-27 using an
Intel Core i7-1185G7, Rust 1.97.1, and `x86_64-pc-windows-msvc`. Each iteration
processes one 16-byte block through the `BlockCipher` API; initialization and
key expansion are outside the timed loop. The AES-NI figures come from the
default-feature build; the portable T-table and light figures come from the
same `--no-default-features` run. Lower latency is better.

Encryption latency:

| Backend | AES-128 | AES-192 | AES-256 |
|---------|--------:|--------:|--------:|
| AES-NI | 12.8 ns | 14.7 ns | 14.7 ns |
| Portable T-table | 65.4 ns | 77.1 ns | 94.4 ns |
| `AesLightEngine` | 104.5 ns | 125.6 ns | 142.9 ns |

Decryption latency:

| Backend | AES-128 | AES-192 | AES-256 |
|---------|--------:|--------:|--------:|
| AES-NI | 12.0 ns | 11.6 ns | 12.7 ns |
| Portable T-table | 68.3 ns | 81.1 ns | 92.2 ns |
| `AesLightEngine` | 157.9 ns | 187.4 ns | 224.2 ns |

On this system, the portable T-table backend was approximately 1.5-1.6x faster
than `AesLightEngine` for encryption and 2.3-2.4x faster for decryption. AES-NI
was approximately 5.1-6.4x faster than the T-table backend for encryption and
5.7-7.3x faster for decryption. Absolute values depend on the processor,
compiler, power state, and operating system, so rerun the benchmark on the
target system before making a performance decision.

## 5. Building and testing

The default build enables `std`. `AesEngine` performs runtime CPU-feature
detection and uses AES-NI when available:

```bash
cargo build -p tc_block_cipher --locked
cargo test -p tc_block_cipher --locked
```

Disable default features for an allocation-free `no_std` build. Every algorithm
is still available; only the AES-NI backend is dropped in favour of the portable
one:

```bash
cargo build -p tc_block_cipher --no-default-features --locked
cargo test -p tc_block_cipher --no-default-features --locked
```

Tests still link the Rust standard test harness, but compile the library with
the selected feature set. Every engine and parameter object stores its material
in fixed-size storage, so a `no_std` application needs no global allocator for
this crate.

Additional validation:

```bash
cargo clippy -p tc_block_cipher --all-targets --locked -- -D warnings
cargo clippy -p tc_block_cipher --all-targets --no-default-features --locked -- -D warnings
cargo rustdoc -p tc_block_cipher --locked -- -D warnings
```

Run the AES benchmarks with:

```bash
# Runtime-dispatched backend; AES-NI is used when available.
cargo bench -p tc_block_cipher --bench aes --locked

# Force the portable AesEngine backend and compare it with AesLightEngine.
cargo bench -p tc_block_cipher --bench aes --no-default-features --locked
```
