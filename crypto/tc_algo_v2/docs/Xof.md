# XOFs

An extendable-output function hashes a message into as many bytes as you ask for, where a digest
gives a fixed size. The length is not set in advance: it is given when the output is taken, and the
shorter of two outputs is the start of the longer.

With SHAKE256, whose row is behind the `shake256` feature.

```rust
use tc_algo_v2::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let message = b"attack at dawn";

    let mut xof = algo.xof().get_by_name("SHAKE256")?;
    xof.update(message);

    // Take the output in pieces
    let mut first = [0; 32];
    xof.output(&mut first);
    let rest = xof.finalize_len(32);

    // The same with a helper
    let output = algo.xof().calculate_by_name("SHAKE256", message, 64)?;

    assert_eq!([&first[..], &rest[..]].concat(), output);
    Ok(())
}
```

## Algorithms

| Name | Aliases | OIDs | Feature | Params | Note |
|---|---|---|---|---|---|
| `SHAKE128` | `SHAKE-128` | `2.16.840.1.101.3.4.2.11` | `shake128` |  |  |
| `SHAKE256` | `SHAKE-256` | `2.16.840.1.101.3.4.2.12` | `shake256` |  |  |
| `CSHAKE128` |  |  | `cshake128` | `CShakeParams` |  |
| `CSHAKE256` |  |  | `cshake256` | `CShakeParams` |  |
| `TUPLEHASH128` |  |  | `tuplehash128` | `TupleHashParams` | each update is one element |
| `TUPLEHASH256` |  |  | `tuplehash256` | `TupleHashParams` | each update is one element |
| `PARALLELHASH128` |  |  | `parallelhash128` | `ParallelHashParams` | blocks of 8192 bytes by default |
| `PARALLELHASH256` |  |  | `parallelhash256` | `ParallelHashParams` | blocks of 8192 bytes by default |
| `BLAKE2XS` |  |  | `blake2xs` | `Blake2xsParams` | output length not set in advance |
| `BLAKE3` |  |  | `blake3` | `Blake3Params` |  |
| `ASCON-XOF128` |  |  | `ascon-xof128` |  |  |
| `ASCON-CXOF128` |  |  | `ascon-cxof128` | `AsconCXofParams` |  |
| `ASCON-XOF` |  |  | `ascon-xof` |  | pre-standard |
| `ASCON-XOFA` |  |  | `ascon-xofa` |  | pre-standard |

The case of a name does not matter. Bouncy Castle has no factory of XOFs; the SHAKE rows are
named as its `DigestUtilities` names SHAKE, and the others by the names of their XOFs, with no
alias or OID. A pre-standard XOF is the Ascon of before NIST's SP 800-232, for old data only.
`BLAKE2XS` is BLAKE2xs of an unknown output length, so the output does not depend on the length
asked for. TupleHash takes each `update` as one element of the tuple, as Bouncy Castle does, so
a message given in two updates hashes as another tuple than in one.

## Params

`init` is optional, and starts a new message; `reset` keeps what it set. Without it, each XOF
runs with nothing set: empty strings, no key. One with nothing to set refuses any params with
`InvalidParams`, as does one given params of another type or of a length it does not take. The
helpers ending in `_with` call `init` first, and the others do not call it.

- `CShakeParams`: the function name N and the customization string S of SP 800-185. Both empty
  is SHAKE.
- `TupleHashParams`: the customization string S of SP 800-185.
- `ParallelHashParams`: the block size B in bytes, more than 0, and the customization string S
  of SP 800-185. SP 800-185 has no default B, and B is part of what is hashed: without `init`,
  ParallelHash runs with blocks of 8192 bytes, a choice of this crate, so another
  implementation gives the same output only when given that block size too.
- `AsconCXofParams`: the customization string Z of SP 800-232, at most 256 bytes.
- `Blake2xsParams`: a key of at most 32 bytes, a salt of 8 and a personalization of 8, each
  optional.
- `Blake3Params`: `keyed` with a 32-byte key, for the keyed hash, or `derive_key` with a context
  string, for key derivation, after Bouncy Castle's `Blake3Parameters`.


## Using it

- `update` panics once output has begun, since the input is then closed. Bouncy Castle throws here.
- `output` can be called again for the next bytes.
- `output_final` fills a buffer with the next bytes and starts the next message, and `finalize_len`
  does the same with a `Vec` of the length asked for. `reset` discards the message so far.
- An `Xof` is also a `Digest`, as in Bouncy Castle: `do_final` and `finalize` give `digest_size` bytes
  of output, 64 for SHAKE256, and start the next message. On Rust 1.85 a `Box<dyn Xof>` does not
  convert to a `Box<dyn Digest>`, but it does go to a function generic over `Digest + ?Sized`.
