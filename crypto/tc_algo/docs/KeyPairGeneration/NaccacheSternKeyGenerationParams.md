# NaccacheSternKeyGenerationParams

Enable the `naccache-stern` feature to use the `NACCACHESTERN` key pair generator. Import
`NaccacheSternKeyGenerationParams` from `tc_algo::params::generate`, and the key types from
`tc_algo::params::key`.

## Generate a key pair

```rust
use tc_algo::params::generate::NaccacheSternKeyGenerationParams;
use tc_algo::params::key::{NaccacheSternPrivateKey, NaccacheSternPublicKey};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // A 768-bit n, a certainty of 8 and 30 small primes, as in Bouncy Castle's tests
    let params = NaccacheSternKeyGenerationParams::new(768, 8, 30);
    let pair = algo.key_pair_generator().generate_by_name_with("NACCACHESTERN", &params)?;

    let public = pair
        .public()
        .as_any()
        .downcast_ref::<NaccacheSternPublicKey>()
        .expect("a NaccacheSternPublicKey");
    let private = pair
        .private()
        .as_any()
        .downcast_ref::<NaccacheSternPrivateKey>()
        .expect("a NaccacheSternPrivateKey");

    // The private key holds its public key
    assert_eq!(private.public_key().n(), public.n());
    Ok(())
}
```

The generator returns a `KeyPair` whose `public()` is a `NaccacheSternPublicKey` and whose
`private()` is a `NaccacheSternPrivateKey`, each inside `Box<dyn Params>`. Unlike DH or ElGamal,
the params are not part of the keys: they only steer the generation. The keys draw from the
source of `DefaultAlgoBuilder::set_rand`.

`NACCACHESTERN` has no default, so `generate_by_name("NACCACHESTERN")` returns `NotInitialized`.
Any params other than a `NaccacheSternKeyGenerationParams` are `InvalidParams`.

## Settings

| Argument of `new` | Setting | Valid range |
|---|---|---|
| `strength` | Size of `n` in bits | Room for `σ` and 50 bits more (below) |
| `certainty` | Prime test certainty | At least 1 |
| `count_small_primes` | Small primes whose product is `σ` | Even, from 30 to 100 |

There are no defaults. Nothing is checked when the params are built; the generator checks them
during `init` and returns `InvalidParams` for values outside these ranges.

`σ` is the product of the first `count_small_primes` odd primes, and a message is a number below
`σ`. `n` must hold `σ`, 48 bits of small factors and at least 2 bits of large ones, so the least
`strength` grows with the count:

| `count_small_primes` | Bits of `σ` | Least `strength` |
|---|---|---|
| 30 | 161 | 211 |
| 50 | 311 | 361 |
| 100 | 738 | 788 |

The least `strength` only makes generation possible. The security of the key rests on factoring
`n`, as for RSA, so 768 bits is far too small to be safe; choosing a safe size is up to the caller.

| Accessor | Returns |
|---|---|
| `strength()` | Size of `n` in bits (`u32`) |
| `certainty()` | Prime test certainty (`u32`) |
| `count_small_primes()` | Count of small primes (`usize`) |

Generating a key is slow, and its time varies with how many candidates it tries.

[Key pair generation](../KeyPairGeneration.md) · [Naccache-Stern](../NaccacheStern.md)
