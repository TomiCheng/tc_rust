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

**Status: Ascon-AEAD128 is implemented.** `ascon_aead128::BorrowedParams`
validates and borrows the fixed-size key and nonce plus optional initial
associated data. `ascon_aead128::Engine` provides allocation-free incremental
encryption, decryption, AAD processing, tag generation and verification, and
output-size queries through the `tc_cipher_core` AEAD traits.

The implementation follows bc-csharp `AsconAead128` at
`20cb1616247e5f79d3dcf662b17ed5beb6922151` and is checked against the official
finalized Ascon-AEAD128 KATs from `ascon/ascon-c`.

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
| [ ] | `AsconEngine` | `engines/` | 1070 | None; `ascon128`, `ascon128a`, `ascon80pq` variants | Dependencies available |
| [ ] | `SparkleEngine` | `engines/` | 1377 | None; `SCHWAEMM128_128`, `SCHWAEMM256_128`, `SCHWAEMM192_192`, `SCHWAEMM256_256` variants | Dependencies available |
| [ ] | `Grain128AeadEngine` | `engines/` | 783 | None (self-contained Grain-128 stream) | Dependencies available |
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
- [ ] Implement the remaining self-contained engines: legacy `AsconEngine`,
  `Grain128AeadEngine`, and `SparkleEngine`. `SparkleEngine` also unblocks the
  ESCH digest.
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

The crate is `no_std`. Whether it will also require `alloc` depends on the
engines as they land, and this document will be updated when it does.
