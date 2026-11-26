# SlhDsaParameters

Enable the `slh-dsa` feature to use the `SLH-DSA` key pair generator. Import `SlhDsaParameters`
from `tc_algo::params::generate`, and the key types from `tc_algo::params::key`.

An `SlhDsaParameters` is both the input of the generator and part of each key, so
`tc_algo::params::key` exports it too. The two paths name the same type.

## Generate a key pair

```rust
use tc_algo::params::generate::SlhDsaParameters;
use tc_algo::params::key::{SlhDsaPrivateKey, SlhDsaPublicKey};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // The parameter set is the input of the generator
    let params: SlhDsaParameters = SlhDsaParameters::SHA2_128F;
    let pair = algo.key_pair_generator().generate_by_name_with("SLH-DSA", &params)?;

    let public = pair.public().as_any().downcast_ref::<SlhDsaPublicKey>().expect("an SlhDsaPublicKey");
    let private = pair.private().as_any().downcast_ref::<SlhDsaPrivateKey>().expect("an SlhDsaPrivateKey");

    // Each key carries its parameter set
    assert_eq!(public.params(), params);
    assert_eq!(private.params(), params);
    assert_eq!(public.encoding().len(), params.public_key_length());
    Ok(())
}
```

The generator returns a `KeyPair` whose `public()` is an `SlhDsaPublicKey` and whose `private()`
is an `SlhDsaPrivateKey`, each inside `Box<dyn Params>`. The keys draw from the source of
`DefaultAlgoBuilder::set_rand`.

`SLH-DSA` has no default parameter set, so `generate_by_name("SLH-DSA")` returns
`NotInitialized`. Any params other than an `SlhDsaParameters` are `InvalidParams`.

## Parameter sets

The twelve sets of FIPS 205. Each is a constant; there is nothing to build or check, and
`SlhDsaParameters::ALL` lists them. A key of one set goes only to the signer rows of the same
name: `SLH-DSA-SHA2-128F` and its prehash row `SLH-DSA-SHA2-128F-WITH-SHA256` for `SHA2_128F`.

The hash is SHA-2 or SHAKE. An `S` set makes small signatures slowly, seconds on a slow machine;
an `F` set makes them fast but larger.

| Constant | Signer row | Security category | Public key bytes | Private key bytes | Signature bytes |
|---|---|---|---|---|---|
| `SlhDsaParameters::SHA2_128S` | `SLH-DSA-SHA2-128S` | 1 | 32 | 64 | 7856 |
| `SlhDsaParameters::SHAKE_128S` | `SLH-DSA-SHAKE-128S` | 1 | 32 | 64 | 7856 |
| `SlhDsaParameters::SHA2_128F` | `SLH-DSA-SHA2-128F` | 1 | 32 | 64 | 17088 |
| `SlhDsaParameters::SHAKE_128F` | `SLH-DSA-SHAKE-128F` | 1 | 32 | 64 | 17088 |
| `SlhDsaParameters::SHA2_192S` | `SLH-DSA-SHA2-192S` | 3 | 48 | 96 | 16224 |
| `SlhDsaParameters::SHAKE_192S` | `SLH-DSA-SHAKE-192S` | 3 | 48 | 96 | 16224 |
| `SlhDsaParameters::SHA2_192F` | `SLH-DSA-SHA2-192F` | 3 | 48 | 96 | 35664 |
| `SlhDsaParameters::SHAKE_192F` | `SLH-DSA-SHAKE-192F` | 3 | 48 | 96 | 35664 |
| `SlhDsaParameters::SHA2_256S` | `SLH-DSA-SHA2-256S` | 5 | 64 | 128 | 29792 |
| `SlhDsaParameters::SHAKE_256S` | `SLH-DSA-SHAKE-256S` | 5 | 64 | 128 | 29792 |
| `SlhDsaParameters::SHA2_256F` | `SLH-DSA-SHA2-256F` | 5 | 64 | 128 | 49856 |
| `SlhDsaParameters::SHAKE_256F` | `SLH-DSA-SHAKE-256F` | 5 | 64 | 128 | 49856 |

| Accessor | Returns |
|---|---|
| `name()` | The name, for instance `"SLH-DSA-SHA2-128s"` (`&'static str`) |
| `n()` | Bytes of the hash output, 16, 24 or 32 (`usize`) |
| `public_key_length()` | Bytes of the public key (`usize`) |
| `private_key_length()` | Bytes of the private key (`usize`) |
| `signature_length()` | Bytes of a signature (`usize`) |

`name()` gives the lowercase `s` or `f` of FIPS 205; the signer rows take any case.
`SlhDsaParameters` is `Copy`, so the keys' `params()` return it by value, and two sets are equal
when they are the same constant.

[Key pair generation](../KeyPairGeneration.md) · [SLH-DSA](../SlhDsa.md)
