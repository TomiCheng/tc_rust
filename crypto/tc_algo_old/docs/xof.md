# XOFs

An extendable-output function hashes a message into as many bytes as you ask for. `algo.xof()`
creates them by name or by OID. Every XOF it creates is an `AnyXof`.

## Enabling XOFs

Nothing is on by default. Each XOF has its own Cargo feature, listed in the [table](#algorithms)
below.

```toml
[dependencies]
tc_algo_old = { version = "0.1", features = ["shake128"] }
```

Family features enable both strengths at once: `shake`, `cshake`, `tuplehash` and `parallelhash`.

## Usage

### An XOF that takes nothing

Get it, feed it, then finish. `finalize` returns the bytes you ask for and starts the next message.

```rust
use tc_algo_old::{Algo, AlgoError};

fn main() -> Result<(), AlgoError> {
    let algo = Algo::new();
    let mut shake = algo.xof().get_by_name("SHAKE128")?;
    shake.update(b"hello, ")?;
    shake.update(b"world")?;
    let output = shake.finalize(64)?;
    assert_eq!(output.len(), 64);
    Ok(())
}
```

### An XOF that takes params

`init` takes an `AnyXofParams`. A field the XOF has no use for is refused, not ignored.

```rust
use tc_algo_old::{Algo, AlgoError, AnyXofParams};

fn main() -> Result<(), AlgoError> {
    let algo = Algo::new();
    let params = AnyXofParams::new()
        .with_customization(b"my application".to_vec())
        .with_block_size(8192);

    let mut xof = algo.xof().get_by_name("PARALLELHASH128")?;
    xof.init(&params)?;
    xof.update(b"hello, world")?;
    let output = xof.finalize(64)?;

    // All at once
    assert_eq!(
        algo.xof().calculate("PARALLELHASH128", &params, b"hello, world", 64)?,
        output
    );
    Ok(())
}
```

### Taking the output in pieces

`output` fills a buffer and stays ready for more. Input after it is refused until `finalize`,
`reset` or `init` starts a new message.

```rust
use tc_algo_old::{Algo, AlgoError};

fn main() -> Result<(), AlgoError> {
    let algo = Algo::new();
    let mut shake = algo.xof().get_by_name("SHAKE256")?;
    shake.update(b"hello, world")?;

    let mut first = [0; 32];
    shake.output(&mut first)?;
    let rest = shake.finalize(32)?;
    assert_eq!(rest.len(), 32);
    Ok(())
}
```

## Algorithms

| Name | OID | Feature | Customization | Function name | Block size |
|---|---|---|:---:|:---:|:---:|
| SHAKE128 | `2.16.840.1.101.3.4.2.11` | `shake128` | | | |
| SHAKE256 | `2.16.840.1.101.3.4.2.12` | `shake256` | | | |
| CSHAKE128 | — | `cshake128` | optional | optional | |
| CSHAKE256 | — | `cshake256` | optional | optional | |
| TUPLEHASH128 | — | `tuplehash128` | optional | | |
| TUPLEHASH256 | — | `tuplehash256` | optional | | |
| PARALLELHASH128 | — | `parallelhash128` | optional | | required |
| PARALLELHASH256 | — | `parallelhash256` | optional | | required |
| BLAKE2XS | — | `blake2xs` | | | |
| BLAKE3 | — | `blake3` | | | |
| ASCON-XOF128 | — | `ascon-xof128` | | | |
| ASCON-CXOF128 | — | `ascon-cxof128` | optional | | |
| ASCON-XOF | — | `ascon-xof-legacy` | | | |
| ASCON-XOFA | — | `ascon-xof-legacy` | | | |

Names match without regard to ASCII case, `SHAKE-128` and `SHAKE-256` are accepted too, and a dotted
OID string works wherever a name does.

## Notes

- **TupleHash**: each `update` is one element of the tuple, so `update(b"ab")` and `update(b"a")`,
  `update(b"b")` give different output. Both are what Bouncy Castle does.
- **TupleHash and ParallelHash have two forms**. Calling `output` first gives the XOF form of NIST
  SP 800-185. Calling `finalize` first gives the fixed-length form, whose padding holds a length:
  for TupleHash the length you ask for, as NIST has it; for ParallelHash its default, 32 bytes for
  the 128 strength and 64 for the 256, as Bouncy Castle has it. So ParallelHash agrees with NIST's
  fixed-length form only at those lengths. Bouncy Castle's TupleHash pads with its default too,
  unless its constructor is given the output size.
- **ParallelHash needs a block size above zero**: until `init` gives one, `update` and `finalize`
  return `NotInitialized`.
- **ASCON-CXOF128** refuses a customization string over 256 bytes.
- **SHAKE as a digest**: `algo.digest()` has `SHAKE128-256` and `SHAKE256-512`, which give a fixed
  32 and 64 bytes, under the same features. KMAC is an XOF in Bouncy Castle too; here it is under
  `algo.mac()`, since it takes a key.
- **Timing**: the XOFs take time that depends on the length of the input and the output, not on the
  bytes.
