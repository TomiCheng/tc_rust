# RSA key pairs

An RSA key pair is a public key anyone may hold and a private key only you hold. Both share a modulus,
the product of two secret primes, and the size of that modulus in bits is the size of the key.

From the params to a new pair. The `rsa` feature of `tc_algo_v2` has the row, and the random source
that the params ask for comes from `rand` and `rand_core`.

```rust
use rand::rngs::SysRng;
use rand_core::UnwrapErr;
use tc_algo_v2::params::{RsaKey, RsaKeyGenerationParamsOwned, RsaKeyParams};
use tc_algo_v2::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // A 2048-bit key
    let params = RsaKeyGenerationParamsOwned::new(UnwrapErr(SysRng)).with_strength(2048);

    // Generate the pair
    let pair = algo.key_pair_generator().generate_by_name_with("RSA", &params)?;

    // Each key is an RsaKey
    let public = pair.public().as_any().downcast_ref::<RsaKey>().expect("an RsaKey");
    let private = pair.private().as_any().downcast_ref::<RsaKey>().expect("an RsaKey");

    assert_eq!(public.modulus(), private.modulus());
    Ok(())
}
```

## Algorithms

| Name | OID | Feature | Params |
|---|---|---|---|
| `RSA` | `1.2.840.113549.1.1.1` | `rsa` | `RsaKeyGenerationParamsOwned` |

The case of the name does not matter.

## Params

The row takes an `RsaKeyGenerationParamsOwned`, and any other type is `InvalidParams`. It starts at
the defaults of Bouncy Castle, and the `with_` methods change them:

| Method | Default | Must be |
|---|---|---|
| `with_strength` | 2048 | at least 16 bits, but use at least 2048 |
| `with_public_exponent` | 65537 | odd, and at least 3 |
| `with_certainty` | 100 | at least 1 |

`init` has `tc_rsa` judge these, so a bad value is `InvalidParams` there and not at `generate`. `tc_rsa`
takes sizes far too small to be safe, so choosing a safe one is up to the caller.

**The random source in the params goes unused.** `new` asks for one, but `init` can only read the
params, so the keys draw from the source of `DefaultAlgoBuilder::set_rand`, which by default is the
operating system's.

## Using it

- `RSA` has no size to assume, so it needs `init`. Use `generate_by_name_with` or
  `generate_by_oid_with`, or `get_by_name`, `init` and `generate`. `generate_by_name` and
  `generate_by_oid` do not call `init`, so with `RSA` they give `NotInitialized`.
- The public key is the modulus and the public exponent. The private key has the CRT values too.
  `RsaKey` wipes itself when dropped, and has no `Debug`, which would show the private values.
- Generating a key is slow, and the larger the key, the slower. Its time varies with how many
  candidates it tries for the primes.
- Each `get_by_name` asks the function given to `set_rand` for a source anew. A function that gives
  the same seed each time makes every generator generate the same key.
- No row of `tc_algo_v2` uses these keys yet: there is no RSA cipher or signer.
