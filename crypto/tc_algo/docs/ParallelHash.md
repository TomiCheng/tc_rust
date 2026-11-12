# ParallelHash

ParallelHash, of NIST SP 800-185, hashes a long message in blocks of B bytes, each hashed on its
own, then hashes the results together. The blocks are independent, so an implementation may hash
them in parallel; this one, as Bouncy Castle's, hashes them in turn. It suits large inputs, such
as files.

`PARALLELHASH128` and `PARALLELHASH256` are behind the `parallelhash128` and `parallelhash256`
features.

## Hashing a file

```rust
use std::fs::File;
use std::io::Read;

use tc_algo::params::ParallelHashParams;
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
        parallel_hash.update(&buffer[..read]);
    }

    // 32 bytes of ParallelHash128
    let hash = parallel_hash.finalize();
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

- **ParallelHash**, of a length set in advance: `finalize` and `do_final` as a `Digest`, 32 bytes
  for `PARALLELHASH128` and 64 for `PARALLELHASH256`. The length is hashed in.
- **ParallelHashXOF**, of any length: `output`, called as many times as needed. A shorter output
  is the start of a longer one.

The first `output` call chooses ParallelHashXOF for the rest of the message.

`finalize_len` and `output_final`, as in Bouncy Castle, hash in the length of `finalize` whatever
length they are asked for: `finalize_len(32)` on `PARALLELHASH128` is ParallelHash of 32 bytes,
but `finalize_len(64)` is not ParallelHash of 64 bytes, and no other implementation gives it. For
another length, use `output`.

## Params

`ParallelHashParams`, from `tc_algo::params`:

- `new(block_size)`: B in bytes, which must be more than 0, and an empty customization string.
- `with_customization(Vec<u8>)`: S, chosen by the application.

B of 0 is `InvalidParams` from `init`, as are params of another type.

## Using it

- `init` starts a new message, and `reset` keeps what it set.
- The message may come in any number of updates, of any size: `update(b"ab")` then `update(b"c")`
  is the same as `update(b"abc")`.
- A small B makes long messages slow: each block costs a hash of its own.
