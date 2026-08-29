# tc_block_modes

## 1. Overview

`tc_block_modes` provides block cipher modes of operation, ported from the
Bouncy Castle C# `Modes` package. A mode adds the state that turns a
single-block permutation into a way of processing a longer message.

Each mode is generic over the underlying cipher and implements the same
[`BlockCipher`](../tc_cipher_core) and `BlockCipherInit` traits that the cipher
itself implements, so a mode can be used anywhere a block cipher is expected.
The crate therefore depends only on the trait crate `tc_cipher_core`; concrete
engines from [`tc_block_cipher`](../tc_block_cipher) are needed only by its
tests.

The crate is `no_std` and requires `alloc`, because a mode composes its
algorithm name (`"AES/CBC"`) at runtime and sizes its state from the cipher's
block size.

> This crate is a learning port and has not received an independent security
> audit. Do not use it as a replacement for an audited cryptographic library.

## 2. Usage

Add the mode crate, the trait crate, and whichever engines are needed:

```toml
[dependencies]
tc_cipher_core = { path = "../tc_cipher_core" }
tc_block_modes = { path = "../tc_block_modes" }
tc_block_cipher = { path = "../tc_block_cipher" }
```

A mode is built by wrapping an engine. Its parameters wrap the engine's own
parameters and add whatever the mode needs — for CBC, an IV:

```rust
use tc_block_cipher::{AesEngine, AesParams};
use tc_block_modes::{CbcBlockCipher, CbcParams, CipherModeError};
use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};

fn main() -> Result<(), CipherModeError<AesEngine>> {
    let key = [0x11u8; 16];
    let iv = [0x22u8; 16];
    let plaintext = [0x33u8; 16];

    let mut cipher = CbcBlockCipher::new(AesEngine::new());

    // The engine's parameters are built first, then wrapped with the IV.
    let key_params = AesParams::new(&key).expect("16 bytes is a valid AES key");
    cipher.init(CipherDirection::Encrypt, &CbcParams::with_iv(key_params, &iv))?;

    let mut ciphertext = [0u8; 16];
    cipher.process_block(&plaintext, &mut ciphertext)?;

    // Parameters are consumed when wrapped, so rebuild them to decrypt.
    let key_params = AesParams::new(&key).expect("16 bytes is a valid AES key");
    cipher.init(CipherDirection::Decrypt, &CbcParams::with_iv(key_params, &iv))?;

    let mut recovered = [0u8; 16];
    cipher.process_block(&ciphertext, &mut recovered)?;
    assert_eq!(recovered, plaintext);

    Ok(())
}
```

Longer messages are fed one block at a time; the mode carries its chaining or
counter state between calls:

```rust
let block_size = cipher.block_size();
for (chunk_in, chunk_out) in input.chunks(block_size).zip(output.chunks_mut(block_size)) {
    cipher.process_block(chunk_in, chunk_out)?;
}
```

Modes that take a feedback size are built with it, and report a `Result` because
the size is a runtime argument:

```rust
let mut cipher = CfbBlockCipher::new(AesEngine::new(), 8)?;   // CFB8
```

All modes report failures through the shared `CipherModeError<E>`, which carries
the underlying cipher's own error in its `BlockCipher` variant.

## 3. Implemented modes

The eight public implementations of Bouncy Castle's `IBlockCipherMode`.

| Mode | Rust type | bc class | Direction | IV |
|------|-----------|----------|-----------|-----|
| ECB | `EcbBlockCipher` | `EcbBlockCipher` | used | none |
| CBC | `CbcBlockCipher` | `CbcBlockCipher` | used | exactly one block |
| CFB | `CfbBlockCipher` | `CfbBlockCipher` | used | up to one block |
| OpenPGP CFB | `OpenPgpCfbBlockCipher` | `OpenPgpCfbBlockCipher` | used | up to one block |
| OFB | `OfbBlockCipher` | `OfbBlockCipher` | ignored | up to one block |
| CTR | `SicBlockCipher` (alias `CtrBlockCipher`) | `SicBlockCipher` | ignored | required, leaving room for the counter |
| GCTR | `GofbBlockCipher` | `GOfbBlockCipher` | ignored | up to one block; 64-bit ciphers only |
| KCTR | `KCtrBlockCipher` | `KCtrBlockCipher` | ignored | required, up to one block |

`Rfc3394WrapEngine`-style aliases are not provided; a mode is written out with
the engine it wraps, e.g. `CbcBlockCipher::new(AesEngine::new())`.

## 4. Behaviour worth knowing

**`block_size` means the mode's unit, not the cipher's.** CFB and OFB work on
segments of `feedback_bits / 8` bytes, so `CfbBlockCipher::new(aes, 8)` reports a
block size of 1 and consumes one byte per `process_block`. Every other mode
reports the underlying cipher's block size.

**"Direction ignored" means encryption and decryption are the same operation.**
OFB, CTR, GCTR, and KCTR produce a keystream that depends only on the key and
IV, so running ciphertext back through the mode recovers the plaintext. Their
`init` still takes a direction, for parity with the trait, but does not use it.
These modes always key the underlying cipher for encryption, as does CFB, which
only ever runs the cipher forwards.

**A short IV is left-padded with zeros**, per FIPS PUB 81, in the modes whose IV
is "up to one block". CBC requires an exact match, and CTR's IV must leave room
for its counter — at most eight bytes and no more than half the block. An
unusable length is reported as `CipherModeError::InvalidIvLength`.

**Parameters are consumed when wrapped.** `CbcParams::with_iv(key_params, &iv)`
takes ownership of the engine parameters, so rebuild them for a second `init`.

**KCTR implements the stream interface too.** It produces keystream a byte at a
time, so it implements `StreamCipher` and `StreamCipherInit` as well as the
block traits, matching bc. Both pairs declare `algorithm_name` and `init`, so
with both traits in scope a call must name the trait:
`StreamCipherInit::init(&mut mode, &params)`.

**No padding, and no partial blocks.** These modes transform whole units only.
Padding and buffering — bc's `BufferedBlockCipher` and `PaddedBufferedBlockCipher`
— are a separate layer that this crate does not provide, which is also why
`CtsBlockCipher` is absent: ciphertext stealing needs to hold back the final two
blocks until the message ends.

## 5. Building and testing

```bash
cargo build -p tc_block_modes --locked
cargo test -p tc_block_modes --locked
```

Additional validation:

```bash
cargo clippy -p tc_block_modes --all-targets --locked -- -D warnings
cargo rustdoc -p tc_block_modes --locked -- -D warnings
```

The tests are known-answer tests against published vectors: FIPS-197 for ECB,
NIST SP 800-38A for CBC, CFB, OFB, and CTR, and the Bouncy Castle
`GOST28147Test` and `DSTU7624Test` vectors for GCTR and KCTR. OpenPGP CFB has no
published vectors, so it is pinned structurally instead — its first block must
equal plain CFB and its third must differ, which is what the resynchronisation
step causes.
