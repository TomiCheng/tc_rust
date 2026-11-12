# DRBG

A deterministic random bit generator stretches a little entropy into as many random bytes as
wanted. It is seeded from a true random source, and from then on its output follows from its state,
so a whole program can draw from one generator without asking the operating system each time. NIST
SP 800-90A defines three kinds, over HMAC, over a hash, and over a block cipher in CTR mode.

A DRBG here is a random source in its own right: it implements `rand_core`'s `CryptoRng`, so it can
be given wherever one is wanted. The `drbg-hmac-sha256` feature of `tc_algo` has the row.

```rust
use rand_core::Rng;
use tc_algo::params::DrbgParams;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // Seeded when it is created, so it works at once
    let mut drbg = algo.drbg().get_by_name("HMAC/SHA-256")?;
    let number = drbg.next_u64();
    let mut key = [0; 32];
    drbg.fill_bytes(&mut key);

    // Seeded again, with a personalization string of its own
    drbg.init(&DrbgParams::new().with_personalization(b"my app v1".to_vec()))?;

    // New entropy, mixed with some input of the caller's
    drbg.reseed(b"additional input")?;

    let _ = (number, key);
    Ok(())
}
```

## Algorithms

| Name | Feature | Security strength | Entropy bytes | Nonce bytes |
|---|---|---|---|---|
| `HMAC/SHA-256` | `drbg-hmac-sha256` | 256 bits | 32 | 16 |

`HMAC/SHA256` finds it too, and the case of a name does not matter. A DRBG has no OID. Bouncy Castle
has no names for its DRBGs, so these are the `Mechanism/Base` of SP 800-90A; the others to come are
`HASH/SHA-256` and `CTR/AES-256` and their kin.

## Params

The rows need no params to work. `init` takes a `DrbgParams`, in `tc_algo::params`, and any other
type is `InvalidParams`:

| Set by | Default |
|---|---|
| `with_nonce` | empty: 16 bytes are drawn from the random source |
| `with_personalization` | empty |

`init` starts the generator over from new entropy with these, so what it gave before tells nothing
about what it gives after.

## Using it

- **The entropy comes from `DefaultAlgoBuilder::set_rand`**, the operating system's by default. A
  source that gives the same bytes each time makes every generator give the same output, which only
  a test should want.
- **Each `get_by_name` gives a new generator** with new entropy. Keep one and draw from it, rather
  than asking for one for each number.
- **It never fails while drawing.** `next_u64` and `fill_bytes` cannot report an error, so the row
  asks SP 800-90A for a long output in pieces of at most 32 KB, and reseeds by itself when the
  generator has given as much as it may between seeds, as Bouncy Castle's `SP800SecureRandom` does.
- **For prediction resistance, reseed before you draw.** `reseed` mixes new entropy into the state,
  so an attacker who once learned the state cannot follow it afterwards. `init` does more: it starts
  over.
- **A personalization string tells instances apart**, such as one per application, and need not be
  secret. It is not a seed: the entropy still comes from the random source.
- The state is secret, as it decides every byte to come, but the generator under it, `tc_drbg`, does
  not promise to wipe it from memory.
