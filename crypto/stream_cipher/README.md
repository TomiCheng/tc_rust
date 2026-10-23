# Stream ciphers

## 1. Overview

The stream-cipher implementations are independent crates under
`crypto/stream_cipher`. They are pure-Rust ports of the Bouncy Castle C#
engine package and implement the `StreamCipher` and `StreamCipherInit` traits
of the published [`tc_stream_cipher`](https://crates.io/crates/tc_stream_cipher).

A stream cipher generates a keystream and XORs it with the input. Encryption
and decryption therefore use the same transformation. The API still requires
an explicit `CipherDirection`; the engines accept the value but generate the
same keystream in both directions.

Salsa20 and XSalsa20 are constant time. HC, RC4, VMPC and ISAAC index tables
with secret state, so they are variable time and exposed to cache-timing
attacks; each engine documents this.

Every implementation crate is unconditionally `no_std` and does not require
`alloc`. Engines keep the required initialization state in fixed-size storage
so that `reset` can reproduce the original keystream.

> These crates are learning ports and have not received an independent
> security audit. Do not use them as replacements for audited cryptographic
> libraries. RC4, VMPC, ISAAC, and several original constructions documented
> below are retained for compatibility and study, not for new protocols.

## 2. Crate layout

| Crate | Algorithms / engines |
|-------|----------------------|
| [`tc_chacha`](https://crates.io/crates/tc_chacha) | `ChaChaEngine`, `ChaCha7539Engine`, `XChaCha20Engine`; published on `tc_stream_cipher` and no longer in this workspace |
| `tc_hc` | `Hc128Engine`, `Hc256Engine` |
| `tc_rc4_family` | `Rc4Engine`, `VmpcEngine`, `VmpcKsa3Engine`, `IsaacEngine`: RC4 and the two designs derived from it |
| `tc_salsa20` | `Salsa20Engine`, `Xsalsa20Engine` |

`tc_salsa20` and `tc_rc4_family` have an optional `rustcrypto` feature, as
`tc_chacha` does: `Salsa20Engine`, `Xsalsa20Engine` and `Rc4Engine` then run on
RustCrypto's `salsa20` and `rc4` where those cover the request, and on the
portable engines otherwise, so the accepted keys and IVs never change. The
`*PortableEngine` and `*RustCryptoEngine` types can also be used directly.

Applications depend only on the implementation crates they use, plus
`tc_stream_cipher` for the traits and parameter containers:

```toml
[dependencies]
tc_stream_cipher = "0.1"
tc_rc4_family = { version = "0.1", path = "../tc_rust/crypto/stream_cipher/tc_rc4_family" }
```

Adjust the paths for the application's location. Keeping both `version` and
`path` lets Cargo verify the local crate version during development; a
published dependency can later omit `path`.

## 3. Parameters and usage

Initialization parameters are shared through the `KeyParams` and `IvParams`
traits of `tc_stream_cipher`:

- Algorithms that need only a key accept any `KeyParams`.
- Algorithms that need a key and IV require both `KeyParams` and `IvParams`.
- `KeyRef` and `KeyWithIvRef` borrow caller-owned bytes without allocation.
- `KeyFixed` and `KeyWithIvFixed` own fixed-size arrays; `KeyOwned` and
  `KeyWithIvOwned` own heap buffers with the `alloc` feature. The owning
  containers wipe their bytes on drop.
- Applications may implement either parameter trait on their own types.

The wrappers do not validate lengths. Each engine applies its own key and IV
rules during `init` and returns `InitError` for invalid parameters.

### Key-only example

```rust
use tc_rc4_family::Rc4Engine;
use tc_stream_cipher::{CipherDirection, KeyRef, StreamCipher, StreamCipherInit};

let params = KeyRef::new(b"Key");
let plaintext = b"Plaintext";
let mut cipher = Rc4Engine::new();

cipher.init(CipherDirection::Encrypt, &params).unwrap();
let mut ciphertext = [0u8; 9];
assert_eq!(
    cipher.process_bytes(plaintext, &mut ciphertext),
    Ok(plaintext.len()),
);

cipher.init(CipherDirection::Decrypt, &params).unwrap();
let mut recovered = [0u8; 9];
cipher.process_bytes(&ciphertext, &mut recovered).unwrap();
assert_eq!(&recovered, plaintext);
```

### Key-and-IV example

```rust
use tc_salsa20::Salsa20Engine;
use tc_stream_cipher::{CipherDirection, KeyWithIvRef, StreamCipher, StreamCipherInit};

let key = [0u8; 32];
let iv = [0u8; Salsa20Engine::IV_BYTES];
let params = KeyWithIvRef::new(&key, &iv);
let mut cipher = Salsa20Engine::new();

cipher.init(CipherDirection::Encrypt, &params).unwrap();
let mut output = [0u8; 64];
cipher.process_bytes(&[0u8; 64], &mut output).unwrap();
```

`process_bytes` writes exactly one output byte for each input byte. The output
slice must therefore be at least as long as the input slice. `return_byte`
processes one byte, while `reset` restarts the keystream using the parameters
from the most recent successful `init` call.

After initialization, engines with the same processing error type can be used
through `dyn StreamCipher<Error = StreamError>`. Initialization is independent:
`StreamCipherInit<P>` can accept caller-owned parameter types and can itself be
used through a trait object when `P` and the initialization error are fixed.

Never reuse a key and IV pair. Keystream reuse can reveal relationships
between plaintexts even when the cipher itself is implemented correctly.

## 4. Algorithm inventory

The Bouncy Castle C# `engines` directory contains 11 public stream-cipher
engine types in six families. All 11 are implemented.

| Family | Engine | Key size | IV size | Crate |
|--------|--------|----------|---------|----------|
| RC4 | `Rc4Engine` | 1-256 bytes | None | `tc_rc4_family` |
| HC | `Hc128Engine` | 16 bytes | 16 bytes | `tc_hc` |
| HC | `Hc256Engine` | 16 or 32 bytes | At least 16 bytes | `tc_hc` |
| ISAAC | `IsaacEngine` | 0-1024 bytes | None | `tc_rc4_family` |
| Salsa | `Salsa20Engine` | 16 or 32 bytes | 8 bytes | `tc_salsa20` |
| Salsa | `Xsalsa20Engine` | 32 bytes | 24 bytes | `tc_salsa20` |
| ChaCha | `ChaChaEngine` | 16 or 32 bytes | 8 bytes | `tc_chacha` (published) |
| ChaCha | `ChaCha7539Engine` | 32 bytes | 12 bytes | `tc_chacha` (published) |
| ChaCha | `XChaCha20Engine` | 32 bytes | 24 bytes | `tc_chacha` (published) |
| VMPC | `VmpcEngine` | 16-64 bytes | 16-64 bytes | `tc_rc4_family` |
| VMPC | `VmpcKsa3Engine` | 16-64 bytes | 16-64 bytes | `tc_rc4_family` |

The inventory deliberately excludes:

- `KCtrBlockCipher`, which is a block-cipher counter mode;
- `StreamBlockCipher`, which is an adapter rather than an algorithm;
- ChaCha20-Poly1305 and XChaCha20-Poly1305, which belong to the authenticated
  cipher API.

## 5. Algorithm notes

### ChaCha family

`ChaChaEngine` is the original construction with a 64-bit counter and 8-byte
IV. It accepts 16- or 32-byte keys and uses 20 rounds by default;
`with_rounds` also supports positive, even custom counts such as 8 and 12.

`ChaCha7539Engine` is the IETF construction with a 32-byte key, 12-byte IV,
and 32-bit block counter. `XChaCha20Engine` accepts a 24-byte IV and derives a
subkey with HChaCha20. Tests cover BC vectors, RFC 8439, the XChaCha draft,
HChaCha20 derivation, output limits, and counter exhaustion.

### Salsa20 family

`Salsa20Engine` accepts a 16- or 32-byte key and 8-byte IV. It uses 20 rounds
by default, while `with_rounds` supports positive, even custom counts.
`Xsalsa20Engine` uses a 32-byte key, 24-byte IV, and HSalsa20 subkey
derivation. Both preserve BC's per-IV output-limit behavior.

### HC family

`Hc128Engine` requires a 16-byte key and IV. `Hc256Engine` preserves current
Bouncy Castle compatibility behavior: it accepts 16- or 32-byte keys and IVs
of at least 16 bytes, then normalizes them to 32-byte internal inputs. IV bytes
after the first 32 are ignored.

### ISAAC

`IsaacEngine` preserves BC's byte ordering and accepts zero through 1024 key
bytes. ISAAC is primarily a pseudorandom generator and is retained here for
BC compatibility rather than recommended modern encryption.

### VMPC and VMPC-KSA3

Both engines accept independently sized 16-64 byte keys and IVs. VMPC
schedules key then IV; VMPC-KSA3 performs key, IV, then key scheduling. Tests
reproduce BC's one-million-byte checkpoints.

### RC4

`Rc4Engine` accepts 1-256 key bytes. RC4 has serious statistical biases and is
prohibited by modern protocols such as TLS. It is included only for legacy
compatibility, study, and data migration.

## 6. Building and testing

Run every stream-cipher test suite from the workspace root:

```bash
cargo test -p tc_hc -p tc_rc4_family -p tc_salsa20 --locked
```

Run Clippy for all library and test targets:

```bash
cargo clippy -p tc_hc -p tc_rc4_family -p tc_salsa20 --all-targets --locked -- -D warnings
```

Rustdoc accepts one package at a time:

```bash
cargo rustdoc -p tc_hc --locked -- -D warnings
cargo rustdoc -p tc_rc4_family --locked -- -D warnings
cargo rustdoc -p tc_salsa20 --locked -- -D warnings
```

The tests use Rust's standard test harness, but each library remains `no_std`
and needs no allocator.
