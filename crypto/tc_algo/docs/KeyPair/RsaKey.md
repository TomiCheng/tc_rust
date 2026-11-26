# RsaKey

Enable the `rsa` feature to use `RsaKey`. Import it, `RsaKeyOwned`, `RsaPrivateCrtKeyOwned` and the
`RsaKeyParams`, `RsaPrivateCrtKeyParams` and `AsymmetricKeyParams` traits from
`tc_algo::params::key`. The `RSA` key pair generator returns an `RsaKey` for both keys of a pair;
the variant tells how the key is raised.

| Variant | What it is | From the generator |
|---|---|---|
| `RsaKey::Core` | A modulus and one exponent | The public key |
| `RsaKey::Crt` | A private key with its CRT values | The private key |

## Fields

| Field | What it is | `Core` | `Crt` | Accessor |
|---|---|---|---|---|
| `n` | The modulus | yes | yes | `RsaKeyParams::modulus()` |
| `e` | The public exponent | as the exponent of a public key | yes | `RsaKeyParams::exponent()`; `public_exponent()` on `Crt` |
| `d` | The private exponent | as the exponent of a private key | yes | `RsaKeyParams::exponent()` |
| `p`, `q` | The primes of `n` | | yes | `p()`, `q()` |
| `dp`, `dq` | `d mod (p - 1)` and `d mod (q - 1)` | | yes | `dp()`, `dq()` |
| `q_inv` | `q⁻¹ mod p` | | yes | `q_inv()` |
| `is_private` | Whether the exponent is `d` | yes | always private | `AsymmetricKeyParams::is_private_key()` |

Each number is a `&PaddedBigUint`, and `is_private` a `bool`. The accessors of `Crt` are those of
`RsaPrivateCrtKeyParams`, on the key the variant holds. A key is built from the same fields:

| Build | Gives |
|---|---|
| `RsaKey::from(RsaKeyOwned::new(is_private, n, exponent))` | `RsaKey::Core`: `false` with `e` for a public key, `true` with `d` for a private one |
| `RsaKey::from(RsaPrivateCrtKeyOwned::new(n, e, d, p, q, dp, dq, q_inv))` | `RsaKey::Crt` |

The values are `PaddedBigUint` of `tc_bigint`, which `tc_algo` does not re-export; values read from
another key, as the example does, need no import. `RsaKeyParams::validate()` tells whether a key
passes its checks.

An `RsaKey` holds the values at a fixed width, leading zeros and all, so that its storage never
shows how large a private value is. It is a container: nothing is checked when it is built, and
the cipher or signer that takes it calls `validate` once at `init`, which checks an odd modulus of
at most 16384 bits with no small prime factor and a nonzero exponent, odd for a public key. The
keys the generator returns have passed already. The key is wiped when it is dropped, and there is
no `Debug`, which would show the private values.

## Read and build a key pair

```rust
use tc_algo::params::generate::RsaKeyGenParams;
use tc_algo::params::key::{
    RsaKey, RsaKeyOwned, RsaKeyParams, RsaPrivateCrtKeyOwned, RsaPrivateCrtKeyParams,
};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let pair = algo.key_pair_generator().generate_by_name_with("RSA", &RsaKeyGenParams::new(2048))?;

    let public = pair.public().as_any().downcast_ref::<RsaKey>().expect("an RsaKey");
    let private = pair.private().as_any().downcast_ref::<RsaKey>().expect("an RsaKey");

    // The generator's private key always has its CRT values
    let RsaKey::Crt(crt) = private else {
        unreachable!("the generator gives a CRT private key");
    };
    // Build the same keys again from their fields
    let _public1 = RsaKey::from(RsaKeyOwned::new(
        false,
        public.modulus().clone(),
        public.exponent().clone(),
    ));
    let _private1 = RsaKey::from(RsaPrivateCrtKeyOwned::new(
        crt.modulus().clone(),
        crt.public_exponent().clone(),
        crt.exponent().clone(),
        crt.p().clone(),
        crt.q().clone(),
        crt.dp().clone(),
        crt.dq().clone(),
        crt.q_inv().clone(),
    ));
    Ok(())
}
```

## Use it with an algorithm

| Rows | Public key | Private key |
|---|---|---|
| RSA ciphers, such as `RSA//OAEPWITHSHA256ANDMGF1PADDING` | Encrypts | Decrypts |
| RSA signers, such as `SHA-256withRSA` and `SHA-256withRSAandMGF1` | Verifies | Signs |

The keys of a pair go straight in, as `pair.public()` and `pair.private()`. A private key without
its CRT values, an `RsaKey::Core`, works too, only slower.

[Key pair generation](../KeyPairGeneration.md) · [RSA](../Rsa.md) ·
[RsaKeyGenParams](../KeyPairGeneration/RsaKeyGenParams.md)
