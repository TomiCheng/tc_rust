# Block ciphers (legacy traits)

This directory holds the last block cipher on the legacy `tc_cipher` and
`tc_params` traits: `tc_dstu7624`, DSTU 7624:2014 (Kalyna) with 128-, 256- and
512-bit blocks. It stays only while `crypto/macs/tc_dstu_macs` uses it; DSTU
7624 itself is published on the `tc_block_cipher` traits as
[`tc_dstu7624`](https://crates.io/crates/tc_dstu7624).

> This crate is a learning port and has not received an independent security
> audit. Do not use it as a replacement for audited cryptographic libraries.

## Usage

```toml
[dependencies]
tc_dstu7624 = { version = "0.1", path = "crypto/block_cipher/tc_dstu7624" }
tc_cipher = { version = "0.1", path = "crypto/tc_cipher" }
tc_params = { version = "0.1", path = "crypto/tc_params" }
```

```rust
use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_dstu7624::Engine128;
use tc_params::KeyRef;

fn main() -> Result<(), Box<dyn core::error::Error>> {
    let key = [0x11u8; 16];
    let plaintext = [0x22u8; 16];

    let mut cipher = Engine128::new();
    cipher.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
    let mut ciphertext = [0u8; 16];
    cipher.process_block(&plaintext, &mut ciphertext)?;

    cipher.init(CipherDirection::Decrypt, &KeyRef::new(&key))?;
    let mut recovered = [0u8; 16];
    cipher.process_block(&ciphertext, &mut recovered)?;
    assert_eq!(recovered, plaintext);
    Ok(())
}
```

`Engine128`, `Engine256` and `Engine512` select the block size; each accepts a
key of one or two blocks where DSTU 7624 defines it, through `dyn KeyParams`.

## Graduated block ciphers

AES, ARIA, Camellia, DES and Triple DES, DSTU 7624, GOST 28147-89, RC2, RC5,
RC6, SM4 and Threefish are published from the
[tc_block_cipher](https://github.com/TomiCheng/tc_block_cipher) repository.
Blowfish, CAST5/CAST6, IDEA, Noekeon, Rijndael, SEED, Serpent, SKIPJACK,
TEA/XTEA and Twofish continue in the top-level `block_cipher` directory on the
`tc_block_cipher` traits.

## Building and testing

```bash
cargo build -p tc_dstu7624 --locked
cargo test -p tc_dstu7624 --locked
cargo clippy -p tc_dstu7624 --all-targets --locked -- -D warnings
```
