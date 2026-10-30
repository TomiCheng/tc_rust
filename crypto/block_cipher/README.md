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

> These crates are learning ports and have not received an independent
> security audit. Do not use them as replacements for audited cryptographic
> libraries.

## Usage

Add the selected algorithm crate together with the shared cipher and parameter
crates. Local development can use paths; published applications can replace
them with compatible crates.io versions.

```toml
[dependencies]
tc_des = { version = "0.1", path = "crypto/block_cipher/tc_des" }
tc_cipher = { version = "0.1", path = "crypto/tc_cipher" }
tc_params = { version = "0.1", path = "crypto/tc_params" }
```

Import `BlockCipherInit` to initialize an engine and `BlockCipher` to process a
block. `CipherDirection` explicitly selects encryption or decryption.

```rust
use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_des::{BLOCK_BYTES, DesEngine, KEY_BYTES};
use tc_params::KeyRef;

fn main() -> Result<(), Box<dyn core::error::Error>> {
    let key = [0x11u8; KEY_BYTES];
    let plaintext = [0x22u8; BLOCK_BYTES];

    let mut cipher = DesEngine::new();
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

Both engines accept `dyn KeyParams`, so `KeyRef::new(key)` is sufficient. DSTU
7624 selects its block size through its engine type; the key size remains an
initialization parameter where the algorithm permits more than one for that
block.

Because initialization uses object-safe parameter traits, an application can
keep its key material in its own type instead of converting it to an
algorithm-owned parameter object.

## Implemented algorithms

All migrated implementations have known-answer tests; selected algorithms also
include specification, Monte Carlo, or backend-equivalence tests.

| Status | Crate | Public engines | Key and block support |
|:------:|-------|----------------|-----------------------|
| ✅ | [`tc_des`](tc_des) | `DesEngine`, `DesEdeEngine` | 64-bit block; 8-byte DES or 16/24-byte EDE keys |
| ✅ | [`tc_dstu7624`](tc_dstu7624) | `Engine128`, `Engine256`, `Engine512` | 128/256/512-bit blocks; same-size or double-size keys where defined |

Legend: ✅ migrated and tested, ⬜ TODO.

AES and ARIA have moved to the published
[`tc_aes`](https://crates.io/crates/tc_aes) and
[`tc_aria`](https://crates.io/crates/tc_aria) crates.
RC2, RC5 and RC6 have moved to the published
[`tc_rc_cipher`](https://crates.io/crates/tc_rc_cipher) crate.
Camellia has moved to the published
[`tc_camellia`](https://crates.io/crates/tc_camellia) crate.
SM4 has moved to the published [`tc_sm4`](https://crates.io/crates/tc_sm4)
crate.
Threefish has moved to the published
[`tc_threefish`](https://crates.io/crates/tc_threefish) crate.
GOST 28147-89 has moved to the published
[`tc_gost28147`](https://crates.io/crates/tc_gost28147) crate.

DES and DSTU 7624 are published too, as
[`tc_des`](https://crates.io/crates/tc_des) and
[`tc_dstu7624`](https://crates.io/crates/tc_dstu7624); the legacy copies here
stay only while `crypto/macs/tc_iso9797_mac` and `crypto/macs/tc_dstu_macs`
use them. Blowfish, CAST5/CAST6, IDEA, Noekeon, Rijndael, SEED, Serpent,
SKIPJACK, TEA/XTEA and Twofish continue in the top-level `block_cipher`
directory on the `tc_block_cipher` traits.

DES and Triple DES are provided for compatibility, not as recommendations for
new protocols.

## Building and testing

Build or test an individual algorithm crate:

```bash
cargo build -p tc_des --locked
cargo test -p tc_des --locked
```

Validate all block cipher crates through the workspace:

```bash
cargo check --workspace --locked
cargo test --workspace --locked
```

Tests link the Rust standard test harness, but the libraries remain `no_std`.
Additional validation for a selected crate:

```bash
cargo clippy -p tc_des --all-targets --locked -- -D warnings
cargo rustdoc -p tc_des --locked -- -D warnings
```
