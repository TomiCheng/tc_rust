# ParallelHash

ParallelHash is built on the cSHAKE function of [SHA-3](https://en.wikipedia.org/wiki/SHA-3).
NIST SP 800-185 divides the message into blocks of B bytes, each hashed on its
own, then hashes the results together. The blocks are independent, so an implementation may hash
them in parallel; this one, as Bouncy Castle's, hashes them in turn. It suits large inputs, such
as files.

`PARALLELHASH128` and `PARALLELHASH256` are behind the `keccak` feature.

## Hashing a file

```rust
use std::fs::File;
use std::io::Read;

use tc_algo::params::xof::ParallelHashParams;
use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let algo = DefaultAlgoBuilder::default().build();

    // The XOF
    let mut parallel_hash = algo.xof().get_by_name("PARALLELHASH128")?;

    // The block size both sides agreed on, and an optional customization string
    let params = ParallelHashParams::new(8192).with_customization(b"MyApp file v1".to_vec());
    parallel_hash.init(&params)?;

    // The file, in pieces of any size: the XOF cuts its own blocks
    let mut file = File::open("backup.tar")?;
    let mut buffer = vec![0; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        parallel_hash.try_update(&buffer[..read])?;
    }

    // 32 bytes of ParallelHash128
    let hash = parallel_hash.finalize()?;
    Ok(())
}
```

## The block size

The block size B is part of what is hashed: the same file under B = 8192 and B = 4096 gives two
unrelated hashes. SP 800-185 sets no default, so B is something the two sides agree on, as they
agree on the algorithm.

Without `init`, the rows run with B = 8192 bytes, the chunk size of KangarooTwelve. That is this
crate's choice, not the standard's: another implementation gives the same hash only when it is
given 8192 too. To work with others, set B with `init`.

## Fixed length or extendable

SP 800-185 defines two functions:

- **ParallelHash**, of a length set in advance: `finalize` and `try_do_final` as a `Digest`, 32
  bytes for `PARALLELHASH128` and 64 for `PARALLELHASH256`. The length is hashed in.
- **ParallelHashXOF**, of any length: `try_output`, called as many times as needed. A shorter output
  is the start of a longer one.

The first `try_output` call chooses ParallelHashXOF for the rest of the message.

When called first, `finalize_len(n)` and `try_output_final` encode the configured digest size
(256 or 512 bits) and return the requested number of bytes. For example, `finalize_len(64)` on
`PARALLELHASH128` encodes 256 bits and reads 64 bytes. Standard fixed-length ParallelHash128
with a 64-byte output encodes 512 bits.

For ParallelHashXOF, start with `try_output`. A subsequent `finalize_len` or `try_output_final`
reads the next bytes from that same output stream and resets the message.

## Params

`ParallelHashParams`, from `tc_algo::params::xof`:

- `new(block_size)`: B in bytes, which must be more than 0, and an empty customization string.
- `with_customization(Vec<u8>)`: S, chosen by the application.

B of 0 is `InvalidParams` from `init`, as are params of another type.

## Using it

- `init` starts a new message, and `try_reset` keeps what it set.
- The message may come in any number of updates, of any size: `try_update(b"ab")` then `try_update(b"c")`
  is the same as `try_update(b"abc")`.
- A small B makes long messages slow: each block costs a hash of its own.
