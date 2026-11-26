# NaccacheSternPublicKey and NaccacheSternPrivateKey

Enable the `naccache-stern` feature and import `NaccacheSternPublicKey` and
`NaccacheSternPrivateKey` from `tc_algo::params::key`. The `NACCACHESTERN` key pair generator
returns a `NaccacheSternPublicKey` and a `NaccacheSternPrivateKey`; the private key holds its
public key.

## Fields

| Field | What it is | Public key | Private key | Accessor |
|---|---|---|---|---|
| `g` | The generator | yes | in its public key | `g()` |
| `n` | The modulus, a product of two secret primes | yes | in its public key | `n()` |
| `lower_sigma_bound` | The bits of `σ`; a message is a number below `σ` | yes | in its public key | `lower_sigma_bound()` |
| `small_primes` | The small primes whose product is `σ`, in the random order of generation | | yes | `small_primes()` |
| `phi_n` | `φ(n) = (p - 1)(q - 1)` | | yes | `phi_n()` |

`g`, `n` and `phi_n` are `&PaddedBigUint`, `lower_sigma_bound` a `u32` and `small_primes` a
`&[u32]`. The private key gives its public key with `public_key()`, and the public fields
through it. A key is built from the same fields:

| Build | Gives |
|---|---|
| `NaccacheSternPublicKey::new(g, n, lower_sigma_bound)` | The public key |
| `NaccacheSternPrivateKey::new(g, n, lower_sigma_bound, small_primes, phi_n)` | The private key |

The values are `PaddedBigUint` of `tc_bigint`, which `tc_algo` does not re-export; values read from
another key, as the example does, need no import.

Nothing is checked when a key is built. The cipher row checks a key at `init`: that `n` is odd and
above 2, and for a private key that each small prime divides `phi_n`. Both keys are `Clone`. The
public key is `Debug` and `PartialEq`; the private key is neither, and it wipes `phi_n` and the
order of the small primes, which tells which of them belong to `p - 1`, when it is dropped.

## Read and build a key pair

```rust
use tc_algo::params::generate::NaccacheSternKeyGenerationParams;
use tc_algo::params::key::{NaccacheSternPrivateKey, NaccacheSternPublicKey};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let params = NaccacheSternKeyGenerationParams::new(768, 8, 30);
    let pair = algo.key_pair_generator().generate_by_name_with("NACCACHESTERN", &params)?;

    // The keys of the pair
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

    // Build the same keys again from their fields
    let _public1 =
        NaccacheSternPublicKey::new(public.g().clone(), public.n().clone(), public.lower_sigma_bound());
    let _private1 = NaccacheSternPrivateKey::new(
        private.public_key().g().clone(),
        private.public_key().n().clone(),
        private.public_key().lower_sigma_bound(),
        private.small_primes().to_vec(),
        private.phi_n().clone(),
    );
    Ok(())
}
```

## Use it with an algorithm

| Rows | Public key | Private key |
|---|---|---|
| `NACCACHESTERN` | Encrypts | Decrypts |

A public key goes only to encryption and a private key only to decryption; the other way round is
`InvalidParams`.

## Keys that do not match

| Mismatch | When it shows | What happens |
|---|---|---|
| A private key whose small primes do not all divide `phi_n` | `init` | `InvalidParams` |
| A ciphertext of a key with an `n` of another size | `decrypt` | `DataLength` |
| A ciphertext of another key with an `n` of the same size | Only in use | Usually `Ok` with a wrong message; `InvalidCiphertext` only when a residue is not in the key's tables |

Naccache-Stern has no padding, so a ciphertext of another key mostly decrypts to some number below
`σ`. Keep the keys of a pair together, and authenticate what is encrypted.

[Key pair generation](../KeyPairGeneration.md) · [Naccache-Stern](../NaccacheStern.md) ·
[NaccacheSternKeyGenerationParams](../KeyPairGeneration/NaccacheSternKeyGenerationParams.md)
