# Key pair generation

A key pair is a public key, to give to anyone, and a private key, to keep. What the public key
encrypts or checks, only the private key decrypts or signs; two sides with a pair each can agree
on a secret. `algo.key_pair_generator()` makes the pair from a random source. For one secret key
that both sides share, see [Key generation](KeyGeneration.md).

From a name and its params to a new pair, and the pair straight into a cipher:

```rust
use tc_algo::params::RsaKeyGenParams;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let name = "RSA//OAEPWITHSHA256ANDMGF1PADDING";

    // A 2048-bit RSA pair
    let pair = algo
        .key_pair_generator()
        .generate_by_name_with("RSA", &RsaKeyGenParams::new(2048))?;

    // The public key encrypts, and the private key decrypts
    let sealed = algo.cipher().encrypt_by_name(name, pair.public(), b"attack at dawn")?;
    let opened = algo.cipher().decrypt_by_name(name, pair.private(), &sealed)?;
    assert_eq!(opened, b"attack at dawn");
    Ok(())
}
```

## Algorithms

| Name | Aliases | OID | Feature | Params | Public key | Private key | Page |
|---|---|---|---|---|---|---|---|
| `RSA` |  | `1.2.840.113549.1.1.1` | `rsa` | `RsaKeyGenParams` | `RsaKey` | `RsaKey` | [RSA](Rsa.md) |
| `EC` | `ECDH`, `ECIES`, `ECDHC`, `ECMQV`, `ECDSA` | the X9.63 and SEC schemes | `ec` | `EcKeyGenParams` | `EcPublicKey<C>` | `EcPrivateKey<C>` | [EC](Ec.md) |
| `DH` | `DIFFIEHELLMAN` |  | `dh` | `DhParameters` | `DhPublicKey` | `DhPrivateKey` | [Diffie-Hellman](Dh.md) |
| `ML-KEM` |  |  | `ml-kem` | `MlKemParameters` | `MlKemPublicKey` | `MlKemPrivateKey` | [KEM](KEM.md) |
| `ELGAMAL` |  |  | `elgamal` | `ElGamalParameters` | `ElGamalPublicKey` | `ElGamalPrivateKey` | [ElGamal](ElGamal.md) |
| `NACCACHESTERN` |  |  | `naccache-stern` | `NaccacheSternKeyGenerationParams` | `NaccacheSternPublicKey` | `NaccacheSternPrivateKey` | [Naccache-Stern](NaccacheStern.md) |
| `SM2` |  |  | `sm2` | none | `EcPublicKey<C>` on sm2p256v1 | `EcPrivateKey<C>` on sm2p256v1 | [SM2](Sm2.md) |

The names, aliases and OIDs are those of Bouncy Castle's `GeneratorUtilities`, but those of
Naccache-Stern and SM2, which it has no names for. The case of a name does not matter. Each page
gives the keys the row makes and what takes them.

## Params

- Every row but `SM2` needs `init`, since none has params to assume: the size of an RSA key, the
  curve of an EC key, the group of DH and ElGamal, the parameter set of ML-KEM. `generate_by_name`
  gives `NotInitialized` there, so use `generate_by_name_with`, or `get_by_name`, `init` and
  `generate`.
- `SM2` has its curve fixed: `generate_by_name` gives a pair at once, and `init` refuses any params
  as `InvalidParams`.
- `init` has the crate underneath judge the params, so a bad one is `InvalidParams` there and not at
  `generate`.

## Using it

- `get_by_name` and `get_by_oid` give a `KeyPairGenerator`, which is a `KeyPairGenerator` and a
  `KeyPairGeneratorInit` of `tc_asym_cipher` with `AlgoError` for its errors, so code written for
  those traits takes it as it is. `generate` can be called again and again for new pairs.
- A pair is a `KeyPair`: `public()` and `private()` lend the keys as `&dyn Params`, which go
  straight into the cipher, signer and agreement rows that take them, and `into_parts()` gives them
  up as `Box<dyn Params>`, as ECIES takes them.
- `as_any().downcast_ref` gives the type of a key, as each page names it.
- Generating an RSA or a Naccache-Stern key is slow, and its time varies with how many candidates
  it tries.
- The keys draw from the source of `DefaultAlgoBuilder::set_rand`, the operating system's unless it
  is given another.
