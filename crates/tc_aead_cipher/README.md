# tc_aead_cipher

`tc_aead_cipher` will provide pure-Rust AEAD ciphers (authenticated encryption
with associated data) ported from the Bouncy Castle C# `IAeadCipher` and
`IAeadBlockCipher` family. An AEAD cipher encrypts a message and authenticates
it together with optional associated data, so decryption rejects a modified
ciphertext, modified associated data, or the wrong key rather than returning
unauthenticated plaintext.

> This is a learning port of Bouncy Castle's C# implementations and has not
> received an independent security audit. Do not use it as a replacement for
> an audited cryptographic library.

**Status: Ascon-AEAD128, legacy Ascon v1.2, SCHWAEMM, and Grain-128AEAD are
implemented.** The finalized Ascon algorithm is exposed through
`ascon_aead128`; the distinct legacy Ascon algorithms are exposed through
`ascon`; all four SCHWAEMM parameter sets are exposed through `sparkle`; and
Grain-128AEAD is exposed through `grain128_aead`. These APIs provide
allocation-free incremental encryption, decryption, AAD processing, tag
generation and verification, and output-size queries through the
`tc_cipher_core` AEAD traits.

The implementation follows bc-csharp `AsconAead128` at
`20cb1616247e5f79d3dcf662b17ed5beb6922151` and is checked against the official
finalized Ascon-AEAD128 KATs from `ascon/ascon-c`.

The legacy implementation follows bc-csharp `AsconEngine` and is checked
against its official Ascon v1.2 KAT files for all three variants. New protocols
should use the finalized `ascon_aead128` algorithm instead.

The SCHWAEMM implementation follows bc-csharp `SparkleEngine` and is checked
against the official SPARKLE v1.2 KAT files for all four parameter sets.

The Grain implementation follows bc-csharp `Grain128AeadEngine` and is checked
against all 1,089 KATs from the Grain-128AEADv2 NIST finalist submission.

## Ascon-AEAD128 usage

```rust
use tc_aead_cipher::ascon_aead128::{BorrowedParams, Engine};
use tc_cipher_core::{AeadCipher, AeadCipherInit, CipherDirection};

# fn example() -> Result<(), tc_aead_cipher::AeadCipherError> {
let key = [0x11; 16];
let nonce = [0x22; 16];
let params = BorrowedParams::new(&key, &nonce)?;
let mut cipher = Engine::new();
cipher.init(CipherDirection::Encrypt, &params)?;
cipher.process_aad_bytes(b"header")?;

let plaintext = b"message";
let mut ciphertext = [0_u8; 7 + 16];
let mut written = cipher.process_bytes(plaintext, &mut ciphertext)?;
written += cipher.do_final(&mut ciphertext[written..])?;
assert_eq!(written, ciphertext.len());
assert_eq!(cipher.mac(), Some(&ciphertext[written - 16..]));
# Ok(())
# }
```

Encryption appends a fixed 16-byte authentication tag. Decryption therefore
accepts `[ciphertext || tag]` and verifies the retained tag in `do_final()`.
`mac()` is `None` until finalization succeeds and then borrows the generated or
verified tag.

The engine streams full blocks during decryption, so `process_bytes()` may
write unauthenticated plaintext before `do_final()` verifies the tag. Do not
release or act on any plaintext until finalization succeeds. A completed engine
cannot be reused: initialize it again with a fresh nonce before the next
encryption operation. Reusing a key/nonce pair breaks AEAD security.

## Legacy Ascon v1.2 usage

Choose the legacy algorithm explicitly when constructing the engine. The
selected variant determines the required key length: 16 bytes for `Ascon128`
and `Ascon128a`, or 20 bytes for `Ascon80pq`. All variants use a 16-byte nonce
and a 16-byte tag.

```rust
use tc_aead_cipher::ascon::{BorrowedParams, Engine, Variant};
use tc_cipher_core::{AeadCipherInit, CipherDirection};

# fn example() -> Result<(), tc_aead_cipher::AeadCipherError> {
let key = [0x11; 16];
let nonce = [0x22; 16];
let params = BorrowedParams::new(&key, &nonce)?;
let mut cipher = Engine::new(Variant::Ascon128);
cipher.init(CipherDirection::Encrypt, &params)?;
# Ok(())
# }
```

## SCHWAEMM usage

Choose one of the four parameter sets when constructing the engine. The
variant determines the exact key, nonce, rate, and tag lengths; `init()` rejects
parameters with lengths that do not match it.

```rust
use tc_aead_cipher::sparkle::{BorrowedParams, Engine, Variant};
use tc_cipher_core::{AeadCipherInit, CipherDirection};

# fn example() -> Result<(), tc_aead_cipher::AeadCipherError> {
let key = [0x11; 16];
let nonce = [0x22; 32];
let params = BorrowedParams::new(&key, &nonce);
let mut cipher = Engine::new(Variant::Schwaemm256_128);
cipher.init(CipherDirection::Encrypt, &params)?;
# Ok(())
# }
```

## Grain-128AEAD usage

Grain-128AEAD encodes the total AAD length before authenticating the AAD.
Declare that length in the parameters so the allocation-free engine can accept
AAD incrementally without buffering it. `new_with_aad()` handles the common
case where all AAD is already available; use `new_with_aad_len()` before
supplying it through `process_aad_bytes()` in chunks.

```rust
use tc_aead_cipher::grain128_aead::{BorrowedParams, Engine};
use tc_cipher_core::{AeadCipher, AeadCipherInit, CipherDirection};

# fn example() -> Result<(), tc_aead_cipher::AeadCipherError> {
let key = [0x11; 16];
let nonce = [0x22; 12];
let aad = b"header";
let params = BorrowedParams::new_with_aad_len(&key, &nonce, aad.len())?;
let mut cipher = Engine::new();
cipher.init(CipherDirection::Encrypt, &params)?;
cipher.process_aad_bytes(aad)?;
# Ok(())
# }
```

Starting message processing before the declared AAD length has been supplied,
or supplying more AAD than declared, returns `AadLengthMismatch`.

## The Bouncy Castle interfaces

`IAeadCipher` (`crypto/modes/IAeadCipher.cs`) describes an incremental
interface: `Init`, `ProcessAadByte` / `ProcessAadBytes`, `ProcessByte` /
`ProcessBytes`, `DoFinal`, `GetMac`, `GetUpdateOutputSize`, `GetOutputSize`,
and `Reset`. Callers provide the output buffer and ask for the required size
first, which matches the caller-buffer convention already used by
[`KeyWrap`](../tc_cipher_core/src/key_wrap.rs) in `tc_cipher_core`.

Implementations may buffer everything until `DoFinal` (packet mode) or emit
output incrementally (streaming mode). In streaming mode, decryption can hand
back unauthenticated plaintext before the `DoFinal` that detects an
authentication failure; the surrounding protocol has to hold that data until
the whole ciphertext is authenticated.

`IAeadBlockCipher` extends `IAeadCipher` for constructions built on a block
cipher, adding `GetBlockSize` and `UnderlyingCipher`.

## Inventory: `IAeadBlockCipher`

Six classes, all in `crypto/modes/`.

| Done | Bouncy Castle class | C# LOC | Underlying dependencies | Workspace status |
| --- | --- | --- | --- | --- |
| [ ] | `GcmBlockCipher` | 1932 | 128-bit block cipher, `IGcmMultiplier` | Needs the `crypto/modes/gcm/` subpackage as well |
| [ ] | `GcmSivBlockCipher` | 1085 | 128-bit block cipher, `IGcmMultiplier` | Shares the `gcm/` subpackage with GCM |
| [ ] | `OcbBlockCipher` | 798 | 128-bit block cipher (two instances) | Dependencies available |
| [ ] | `CcmBlockCipher` | 761 | Block cipher, `CbcBlockCipherMac` | No MAC available yet |
| [ ] | `KCcmBlockCipher` | 645 | DSTU 7624 block/key widths | Dependencies available |
| [ ] | `EaxBlockCipher` | 557 | Block cipher, `CMac` | No MAC available yet |

## Inventory: `IAeadCipher`

Six classes: three stream-oriented modes and three lightweight engines.

| Done | Bouncy Castle class | Location | C# LOC | Underlying dependencies | Workspace status |
| --- | --- | --- | --- | --- | --- |
| [x] | `AsconAead128` | `modes/` | 1005 | None (self-contained permutation) | Implemented and tested |
| [x] | `AsconEngine` | `engines/` | 1070 | None; `ascon128`, `ascon128a`, `ascon80pq` variants | Implemented and tested |
| [x] | `SparkleEngine` | `engines/` | 1377 | None; `SCHWAEMM128_128`, `SCHWAEMM256_128`, `SCHWAEMM192_192`, `SCHWAEMM256_256` variants | Implemented and tested |
| [x] | `Grain128AeadEngine` | `engines/` | 783 | None (self-contained Grain-128 stream) | Implemented and tested |
| [ ] | `ChaCha20Poly1305` | `modes/` | 1004 | `ChaCha7539Engine`, `Poly1305` | Engine available; no MAC available yet |
| [ ] | `XChaCha20Poly1305` | `modes/` | 35 | Subclasses `ChaCha20Poly1305`; HChaCha20 subkey derivation | Follows `ChaCha20Poly1305` |

`AsconAead128` is the finalised NIST version and is separate from the earlier
variants carried by `AsconEngine`. `SparkleEngine` also supplies the
permutation that the ESCH digest needs in `tc_digest`.

The C# line counts include documentation comments and the duplicated
`byte[]` / `Span<byte>` overloads, so the Rust ports will be shorter.

`BufferedAeadCipher`, `BufferedAeadBlockCipher`, `security/CipherUtilities`,
and the `tls/crypto/impl/bc` adapters reference these interfaces but are
consumers rather than implementations, so they are outside this inventory. The
lightweight AEAD engines carried by older Bouncy Castle releases (Elephant,
ISAP, PhotonBeetle, Xoodyak, Romulus) are not present in this baseline.

## Remaining prerequisites

Two pieces are still needed before the remaining inventory can be completed.

1. **A MAC crate.** The workspace has no MAC implementation. `Poly1305` blocks
   `ChaCha20Poly1305` and `XChaCha20Poly1305`, `CMac` blocks `EaxBlockCipher`,
   and `CcmBlockCipher` needs CBC-MAC — either as a port of
   `CbcBlockCipherMac` or built on `tc_block_modes::CbcBlockCipher`.
2. **The `crypto/modes/gcm/` subpackage**, shared by `GcmBlockCipher` and
   `GcmSivBlockCipher`: `GcmUtilities` (406 lines), the basic and 4k/8k/64k
   table multipliers, and the exponentiators.

Everything else the inventory needs is already in the workspace: 128-bit block
ciphers and DSTU 7624 in [`tc_block_cipher`](../tc_block_cipher), and
`ChaCha7539Engine` with XChaCha20 in [`tc_stream_cipher`](../tc_stream_cipher).

## TODO

- [x] Add `AeadCipher` and `AeadCipherInit` to `tc_cipher_core`.
- [x] Implement and test the finalized `ascon_aead128::Engine`.
- [x] Implement and test the legacy `ascon::Engine` variants: `Ascon128`,
  `Ascon128a`, and `Ascon80pq`.
- [x] Implement and test the four `sparkle::Engine` SCHWAEMM variants.
- [ ] Add an SSE2 fast path for `Schwaemm256_256`, matching bc-csharp's
  `SparkleOpt16` optimization while retaining the scalar `no_std` fallback.
  This is a performance TODO; it does not affect algorithm compatibility.
- [x] Implement and test `grain128_aead::Engine`.
- [ ] Reuse the SPARKLE permutation to implement the ESCH digest in
  `tc_digest`.
- [ ] Implement block-cipher constructions: `OcbBlockCipher` and
  `KCcmBlockCipher` first, then the `gcm/` subpackage with `GcmBlockCipher` and
  `GcmSivBlockCipher`, followed by `CcmBlockCipher` once CBC-MAC is available.
- [ ] Implement the MAC-dependent constructions: `EaxBlockCipher`,
  `ChaCha20Poly1305`, and `XChaCha20Poly1305`, after a MAC crate exists.

## Build and test

From the workspace root:

```text
cargo build -p tc_aead_cipher --locked
cargo test -p tc_aead_cipher --locked
cargo clippy -p tc_aead_cipher --all-targets --locked -- -D warnings
cargo rustdoc -p tc_aead_cipher --locked -- -D warnings
```

The crate is `no_std` and allocation-free by default. Enable the `alloc`
feature to add `OwnedParams` to the `ascon_aead128`, `ascon`, `sparkle`, and
`grain128_aead` modules. The owned forms copy key and nonce material and store
arbitrary-length initial AAD in a `Vec<u8>`:

```text
cargo build -p tc_aead_cipher --features alloc --locked
```
