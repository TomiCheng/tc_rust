# DefaultAlgoBuilder

`DefaultAlgoBuilder` makes the [`Algo`](crate::Algo) that every factory hangs from. `default()`
starts with the rows of every feature that is on, and `build()` turns the builder into an `Algo`.
Between the two, three things can change what the `Algo` holds:

- **`reg_*`** registers more rows: an algorithm of your own, or another name for one.
- **`set_policy`** decides which rows `algorithms()` lists.
- **`set_rand`** gives the random source that keys, IVs, padding and signatures draw from.

A builder can build any number of `Algo`s, and changing it afterwards does not change those
already built.

## Registering rows

There is one `reg_*` per factory: `reg_digest`, `reg_xof`, `reg_cipher`, `reg_mac`, `reg_wrap`,
`reg_key_generator`, `reg_key_pair_generator`, `reg_agreement`, `reg_signer`, `reg_kdf`, `reg_pbe`,
`reg_kem` and `reg_drbg`. Each takes a function that `build()` calls with a
[`DefaultAlgoContext`](crate::DefaultAlgoContext) and that returns the rows: each row has a name,
aliases and OIDs from [`EntryBase`](crate::EntryBase), and creates the algorithm behind them.

The last function registered comes first, and the built-in rows last, so a lookup by a name finds
the newest row with it. That lets a program replace a built-in algorithm; it also means any code
that can reach the builder can, so keep the builder to the code that sets the program up.

A digest of your own, a toy one-byte checksum, registered and found by its name:

```rust
use tc_algo::digest::{Digest, DigestEntry, TryDigest};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder, DefaultAlgoContext, EntryBase, ErrorKind};

// The algorithm: the sum of the bytes, modulo 256. Not a secure digest.
#[derive(Default)]
struct Sum8(u8);

impl TryDigest for Sum8 {
    type Error = AlgoError;

    fn digest_size(&self) -> usize {
        1
    }

    fn byte_length(&self) -> usize {
        1
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), AlgoError> {
        self.0 = input.iter().fold(self.0, |sum, &byte| sum.wrapping_add(byte));
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        let first = output.first_mut().ok_or(AlgoError::new(ErrorKind::DataLength))?;
        *first = self.0;
        self.0 = 0;
        Ok(1)
    }

    fn try_reset(&mut self) -> Result<(), AlgoError> {
        self.0 = 0;
        Ok(())
    }
}

impl Digest for Sum8 {}

// The row: its name and how to make the algorithm.
struct Sum8Row;

impl EntryBase for Sum8Row {
    fn name(&self) -> &str {
        "SUM8"
    }
}

impl DigestEntry for Sum8Row {
    fn create(&self) -> Box<dyn Digest> {
        Box::new(Sum8::default())
    }
}

fn rows(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    vec![Box::new(Sum8Row)]
}

fn main() -> Result<(), AlgoError> {
    let mut builder = DefaultAlgoBuilder::default();
    builder.reg_digest(rows);
    let algo = builder.build();

    assert_eq!(algo.digest().calculate_by_name("sum8", &[1, 2, 3])?, [6]);
    Ok(())
}
```

A row that needs random numbers keeps `context.rand()` and calls it when it creates the algorithm,
so it draws from what `set_rand` gave.

## Policy

A [`Policy`](crate::Policy) decides, row by row, whether `algorithms()` lists it.
[`ListPolicy`](crate::ListPolicy) is one made of names: a row named in its deny list is left out,
and when its allow list is not empty, so is a row not named in it. A name matches the row's name or
an alias, without regard to ASCII case. `clear_policy` lists every row again.

**A policy only shapes the list.** `get_by_name` and `get_by_oid` still find a row the policy
leaves out, so a policy tells a user interface or a configuration check what to offer, and is not
a way to stop code from using an algorithm. To keep an algorithm out of a program, leave its
feature off.

```rust
use tc_algo::{AlgoBuilder, DefaultAlgoBuilder, ListPolicy};

let mut builder = DefaultAlgoBuilder::default();
builder.set_policy(ListPolicy::new().with_deny(["NONE"]));
let algo = builder.build();

// NONE, the digest that is always on, is not listed, but is still found by its name.
assert!(algo.digest().algorithms().all(|row| row.name() != "NONE"));
assert!(algo.digest().get_by_name("NONE").is_ok());
```

## Random source

`set_rand` takes a function that returns a fresh random source, and the rows call it whenever they
need one. By default it is the operating system's, which panics if the system cannot give random
numbers. A program changes it to use a hardware generator, a DRBG of its own, or a fixed source in
its tests.

```rust
use rand::rngs::SysRng;
use rand_core::{CryptoRng, UnwrapErr};
use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};

// The operating system's random numbers again; a program would put its own source here.
fn system() -> Box<dyn CryptoRng> {
    Box::new(UnwrapErr(SysRng))
}

let mut builder = DefaultAlgoBuilder::default();
builder.set_rand(system);
let algo = builder.build();
# let _ = algo;
```

A source that repeats its output makes every key and signature repeat too, so a fixed source
belongs in tests alone.
