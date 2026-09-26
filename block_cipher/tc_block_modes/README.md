# tc_block_modes

Block-cipher modes of operation (ECB, CBC, CFB, OFB and CTR) for engines that
implement the [`tc_block_cipher`](https://crates.io/crates/tc_block_cipher)
traits, such as [`tc_aes`](https://crates.io/crates/tc_aes). Each mode is
itself a block cipher: initialize it with a key and an IV, then transform one
segment per call. Ported from Bouncy Castle C#.

The crate is `no_std`, needs no allocator by default and contains no `unsafe`
code. It depends on `tc_block_cipher` and
[`tc_zeroize`](https://crates.io/crates/tc_zeroize). Requires Rust 1.85 or
later (edition 2024).

## Modes

- `EcbBlockCipher`: each block on its own. Equal blocks give equal
  ciphertext, so use it only for single blocks or to build other
  constructions.
- `FixedCbcBlockCipher`, `CbcBlockCipher`: CBC over whole blocks, with a
  one-block IV that must be unpredictable for every message.
- `FixedCfbBlockCipher`, `CfbBlockCipher`: CFB with a segment from one byte
  (CFB8) up to one block, and an unpredictable IV.
- `FixedOfbBlockCipher`, `OfbBlockCipher`: OFB. The IV must never repeat under
  one key.
- `FixedSicBlockCipher`, `SicBlockCipher`, also named `FixedCtrBlockCipher`
  and `CtrBlockCipher`: CTR. The IV fills the start of the counter block, and
  a counter block must never repeat under one key.

The `Fixed*` forms take the block size, and the CFB or OFB segment size, as
const generics and keep their state inline. The other forms size their state
at runtime and need the `alloc` feature.

Pass the key and IV in `KeyWithIvRef`, which borrows them, or in
`KeyWithIvFixed` or `KeyWithIvOwned`, which own them and wipe them on drop.
Your own type works too if it implements the engine's key trait and
`IvParams`.

## Features

- `alloc` (off by default): adds the runtime-sized modes and `KeyWithIvOwned`.
  It does not require the standard library.

## Usage

```toml
[dependencies]
tc_block_modes = "0.1.0"
tc_block_cipher = "0.1.0"
tc_aes = "0.1.0"
```

```rust
use tc_aes::AesEngine;
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_block_modes::{FixedCbcBlockCipher, KeyWithIvRef};

let (key, iv) = ([0x42; 16], [0x24; 16]); // a fresh, unpredictable IV per message
let mut cbc = FixedCbcBlockCipher::<_, 16>::new(AesEngine::new());
cbc.init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &iv)).expect("valid key and IV");
let mut ciphertext = [0; 16];
cbc.process_block(b"one single block", &mut ciphertext).expect("initialized, whole block");
```

The crate documentation covers the IV rules of each mode, finishing with a
partial segment, and the errors.

## Limitations

- No mode authenticates, so altered ciphertext goes undetected. Use an
  authenticated-encryption construction, or add a MAC over the ciphertext.
- There is no padding. ECB and CBC take whole blocks; CFB, OFB and CTR finish
  a partial segment through a segment-sized buffer.
- Timing is the engine's. The modes add only data-independent work, so they
  are constant time exactly when the engine is; `tc_aes` is with AES-NI or its
  `rustcrypto` feature.
- Mode state is wiped on drop, but not the caller's buffers, not copies left
  in registers or on the stack, and not a value that is leaked or forgotten.
- Not yet ported from Bouncy Castle: OpenPGP CFB, GOFB, KCTR and the
  byte-wise stream interface of CTR.
