# NaccacheSternPublicKey and NaccacheSternPrivateKey

Enable `naccache-stern` and import `NaccacheSternPublicKey` and `NaccacheSternPrivateKey` from
`tc_algo::params::key`. The `NACCACHESTERN` generator returns these types.

## Fields

| Field | What it is | Public key | Private key | Accessor |
|---|---|---|---|---|
| `g` | Generator | yes | yes | `g()` on the public key |
| `n` | Modulus | yes | yes | `n()` on the public key |
| `lower_sigma_bound` | Bit length of the small-prime product | yes | yes | `lower_sigma_bound()` |
| `public` | Public components |  | yes | `public_key()` |
| `small_primes` | Ordered list of small primes |  | yes | `small_primes()` |
| `phi_n` | Totient of the modulus |  | yes | `phi_n()` |

| Build | Gives |
|---|---|
| `NaccacheSternPublicKey::new(g, n, lower_sigma_bound)` | Public key |
| `NaccacheSternPrivateKey::new(g, n, bound, small_primes, phi_n)` | Private key |

The integers are `PaddedBigUint` from `tc_bigint`. Values read from another key need no import.
The constructors store the inputs as supplied. The cipher checks the key during initialization.
Dropping the private key wipes the totient and the small-prime list.
The public key implements `Debug` and `PartialEq`. The private key omits these traits.

## Read and build a key pair

```rust
use tc_algo::params::generate::NaccacheSternKeyGenerationParams;
use tc_algo::params::key::{NaccacheSternPrivateKey, NaccacheSternPublicKey};
use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let algo = DefaultAlgoBuilder::default().build();
    let params = NaccacheSternKeyGenerationParams::new(768, 8, 30);
    let pair = algo.key_pair_generator().generate_by_name_with("NACCACHESTERN", &params)?;

    let public = pair.public().as_any().downcast_ref::<NaccacheSternPublicKey>().unwrap();
    let private = pair.private().as_any().downcast_ref::<NaccacheSternPrivateKey>().unwrap();

    let _public1 = NaccacheSternPublicKey::new(
        public.g().clone(), public.n().clone(), public.lower_sigma_bound(),
    );
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

[Key pair generation](../KeyPairGeneration.md) ·
[NaccacheStern](../NaccacheStern.md) ·
[NaccacheSternKeyGenerationParams](../KeyPairGeneration/NaccacheSternKeyGenerationParams.md)
