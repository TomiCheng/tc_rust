# Block ciphers

## Overview

The crates in this directory provide pure-Rust block cipher implementations
ported from the Bouncy Castle C# engine package. Each algorithm family has its
own crate and implements the shared `BlockCipher` and `BlockCipherInit` traits
from `tc_cipher`.

The implementations are `no_std`. They store keys and expanded schedules in
fixed-size storage and require neither the standard library nor a global
allocator. Initialization takes borrowed, object-safe parameter traits from
`tc_params`; callers can use the provided convenience types or implement the
parameter traits on their own types.

`AesEngine` selects an AES-NI backend on x86 and x86-64 processors that report
AES and SSE2 support. It reads CPUID through `core::arch`, while the
`force-portable-aes` feature removes the accelerated backend. `AesLightEngine`
is always portable and uses less static table storage.

On hosted targets such as Windows and Linux, the operating system manages the
XMM state required by AES-NI. On bare-metal x86, CPUID cannot confirm that the
platform enabled XMM/SSE execution or preserves that state across context
switches. Use `force-portable-aes` unless the platform provides those
guarantees.

> These crates are learning ports and have not received an independent
> security audit. Do not use them as replacements for audited cryptographic
> libraries.

## Usage

Add the selected algorithm crate together with the shared cipher and parameter
crates. Local development can use paths; published applications can replace
them with compatible crates.io versions.

```toml
[dependencies]
tc_aes = { version = "0.1", path = "crypto/block_cipher/tc_aes" }
tc_cipher = { version = "0.1", path = "crypto/tc_cipher" }
tc_params = { version = "0.1", path = "crypto/tc_params" }
```

Import `BlockCipherInit` to initialize an engine and `BlockCipher` to process a
block. `CipherDirection` explicitly selects encryption or decryption.

```rust
use tc_aes::{AesEngine, BLOCK_BYTES};
use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_params::KeyRef;

fn main() -> Result<(), Box<dyn core::error::Error>> {
    let key = [0x11u8; 16];
    let plaintext = [0x22u8; BLOCK_BYTES];

    let mut cipher = AesEngine::new();
    cipher.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;

    let mut ciphertext = [0u8; BLOCK_BYTES];
    let written = cipher.process_block(&plaintext, &mut ciphertext)?;
    assert_eq!(written, BLOCK_BYTES);

    cipher.init(CipherDirection::Decrypt, &KeyRef::new(&key))?;

    let mut recovered = [0u8; BLOCK_BYTES];
    cipher.process_block(&ciphertext, &mut recovered)?;
    assert_eq!(recovered, plaintext);

    Ok(())
}
```

`process_block` processes one block from the beginning of each slice. Both
slices must contain at least `block_size()` bytes. Calling it before `init`
returns `BlockError`; invalid initialization parameters return `InitError`.

Most engines accept `dyn KeyParams`, so `KeyRef::new(key)` is sufficient. The
principal exceptions are:

- `Rc2Engine` accepts `dyn Rc2Params`; `tc_rc2::Params` supplies the key and
  effective key size.
- `Rc532Engine` and `Rc564Engine` accept `dyn Rc5Params`; `tc_rc5::Params`
  supplies the key and runtime round count.
- `Gost28147Engine` requires both `KeyParams` and `SBoxParams`;
  `tc_gost28147::KeyWithSBox` selects the default, named, or custom S-box.
- `ThreefishEngine` requires both `KeyParams` and `TweakParams`;
  `tc_threefish::Params` supplies the key and optional 16-byte tweak.
- DSTU 7624, Rijndael, and Threefish use engine types or const parameters to
  select the block size. Key size remains an initialization parameter wherever
  the algorithm permits more than one key size for that block.

Because initialization uses object-safe parameter traits, an application can
keep its key material in its own type instead of converting it to an
algorithm-owned parameter object.

## Implemented algorithms

All migrated implementations have known-answer tests; selected algorithms also
include specification, Monte Carlo, or backend-equivalence tests.

| Status | Crate | Public engines | Key and block support |
|:------:|-------|----------------|-----------------------|
| ✅ | [`tc_aes`](tc_aes) | `AesEngine`, `AesLightEngine` | 128-bit block; 128/192/256-bit keys; AES-NI where available |
| ✅ | [`tc_aria`](tc_aria) | `AriaEngine` | 128-bit block; 128/192/256-bit keys |
| ✅ | [`tc_blowfish`](tc_blowfish) | `BlowfishEngine` | 64-bit block; 32-448-bit keys |
| ✅ | [`tc_camellia`](tc_camellia) | `CamelliaEngine`, `CamelliaLightEngine` | 128-bit block; 128/192/256-bit keys |
| ✅ | [`tc_cast`](tc_cast) | `Cast5Engine`, `Cast6Engine` | CAST5: 64-bit block, 40-128-bit keys; CAST6: 128-bit block, 128-256-bit keys |
| ✅ | [`tc_des`](tc_des) | `DesEngine`, `DesEdeEngine` | 64-bit block; 8-byte DES or 16/24-byte EDE keys |
| ✅ | [`tc_dstu7624`](tc_dstu7624) | `Engine128`, `Engine256`, `Engine512` | 128/256/512-bit blocks; same-size or double-size keys where defined |
| ✅ | [`tc_gost28147`](tc_gost28147) | `Gost28147Engine` | 64-bit block; 256-bit key; named and custom S-boxes |
| ✅ | [`tc_idea`](tc_idea) | `IdeaEngine` | 64-bit block; 128-bit key |
| ✅ | [`tc_noekeon`](tc_noekeon) | `NoekeonEngine` | 128-bit block and key |
| ✅ | [`tc_rc2`](tc_rc2) | `Rc2Engine` | 64-bit block; variable key and effective key size |
| ✅ | [`tc_rc5`](tc_rc5) | `Rc532Engine`, `Rc564Engine` | 64/128-bit blocks; 1-255-byte key; 0-255 rounds |
| ✅ | [`tc_rc6`](tc_rc6) | `Rc6Engine` | 128-bit block; 1-255-byte key; 20 rounds |
| ✅ | [`tc_rijndael`](tc_rijndael) | `Rijndael128Engine` through `Rijndael256Engine` | 128/160/192/224/256-bit blocks and keys in any combination |
| ✅ | [`tc_seed`](tc_seed) | `SeedEngine` | 128-bit block and key |
| ✅ | [`tc_serpent`](tc_serpent) | `SerpentEngine`, `TnepresEngine` | 128-bit block; 4-32-byte keys in 4-byte steps |
| ✅ | [`tc_skipjack`](tc_skipjack) | `SkipjackEngine` | 64-bit block; 80-bit key |
| ✅ | [`tc_sm4`](tc_sm4) | `Sm4Engine` | 128-bit block and key |
| ✅ | [`tc_tea`](tc_tea) | `TeaEngine`, `XteaEngine` | 64-bit block; 128-bit key |
| ✅ | [`tc_threefish`](tc_threefish) | `Threefish256Engine`, `Threefish512Engine`, `Threefish1024Engine` | 256/512/1024-bit block and matching key; optional 128-bit tweak |
| ✅ | [`tc_twofish`](tc_twofish) | `TwofishEngine` | 128-bit block; 128/192/256-bit keys |

Legend: ✅ migrated and tested, ⬜ TODO.

DES, Triple DES, Blowfish, IDEA, RC2, RC5, SKIPJACK, TEA, XTEA, and other
older designs are provided for compatibility and study, not as recommendations
for new protocols.

## AES performance

AES has three execution strategies:

- `AesEngine` uses AES-NI when an x86/x86-64 processor reports AES and SSE2.
- The same `AesEngine` uses a portable T-table implementation elsewhere.
- `AesLightEngine` uses a smaller portable table representation when static
  footprint matters more than throughput.

The following Criterion point estimates were measured on 2026-08-27 using an
Intel Core i7-1185G7, Rust 1.97.1, and `x86_64-pc-windows-msvc`. Each iteration
processed one 16-byte block; initialization and key expansion were outside the
timed loop. Lower latency is better.

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

On that system, AES-NI was approximately 5.1-6.4x faster than the portable
T-table backend for encryption and 5.7-7.3x faster for decryption. Absolute
values depend on the processor, compiler, power state, and operating system;
rerun the benchmark on the target system before making a performance decision.

## Building and testing

Build or test an individual algorithm crate:

```bash
cargo build -p tc_aes --locked
cargo test -p tc_aes --locked
```

Validate all block cipher crates through the workspace:

```bash
cargo check --workspace --locked
cargo test --workspace --locked
```

Tests link the Rust standard test harness, but the libraries remain `no_std`.
Additional validation for a selected crate:

```bash
cargo clippy -p tc_aes --all-targets --locked -- -D warnings
cargo rustdoc -p tc_aes --locked -- -D warnings
```

Run the AES benchmarks with:

```bash
cargo bench -p tc_aes --bench aes --locked
cargo bench -p tc_aes --bench aes --features force-portable-aes --locked
```

The first command measures the automatically selected `AesEngine` backend;
the second forces its portable T-table backend. Both also measure the
always-portable `AesLightEngine`.
