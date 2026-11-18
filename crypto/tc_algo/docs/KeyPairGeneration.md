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

| Name | Aliases | OID | Feature | Params | Public key | Private key |
|---|---|---|---|---|---|---|
| [`RSA`](Rsa.md) |  | `1.2.840.113549.1.1.1` | `rsa` | `RsaKeyGenParams` | `RsaKey` | `RsaKey` |
| [`EC`](Ec.md) | `ECDH`, `ECIES`, `ECDHC`, `ECMQV`, `ECDSA`, `ECGOST3410`, `ECGOST-3410`, `GOST-3410-2001`, `ECGOST3410-2012`, `GOST-3410-2012` | `1.3.133.16.840.63.0.2`, `.3`, `.16`; `1.3.132.1.11.0` to `.3`; `1.3.132.1.14.0` to `.3`; `1.3.132.1.15.0` to `.3` | `ec-key` | `EcKeyGenParams` | `EcPublicKey<C>` | `EcPrivateKey<C>` |
| [`DH`](Dh.md) | `DIFFIEHELLMAN` |  | `dh` | `DhParameters` | `DhPublicKey` | `DhPrivateKey` |
| [`ML-KEM`](KEM.md) |  |  | `ml-kem` | `MlKemParameters` | `MlKemPublicKey` | `MlKemPrivateKey` |
| [`ELGAMAL`](ElGamal.md) |  |  | `elgamal` | `ElGamalParameters` | `ElGamalPublicKey` | `ElGamalPrivateKey` |
| [`NACCACHESTERN`](NaccacheStern.md) |  |  | `naccache-stern` | `NaccacheSternKeyGenerationParams` | `NaccacheSternPublicKey` | `NaccacheSternPrivateKey` |
| [`SM2`](Sm2.md) |  |  | `sm2` | none | `Sm2PublicKey` | `Sm2PrivateKey` |
| [`Ed25519`](EdDSA.md) | `Ed25519ctx`, `Ed25519ph` | `1.3.101.112` | `cfrg-curves` | none | `Ed25519PublicKey` | `Ed25519PrivateKey` |
| [`Ed448`](EdDSA.md) | `Ed448ph` | `1.3.101.113` | `cfrg-curves` | none | `Ed448PublicKey` | `Ed448PrivateKey` |
| [`X25519`](X25519.md) |  | `1.3.101.110` | `cfrg-curves` | none | `X25519PublicKey` | `X25519PrivateKey` |
| [`X448`](X25519.md) |  | `1.3.101.111` | `cfrg-curves` | none | `X448PublicKey` | `X448PrivateKey` |
| [`ML-DSA`](MlDsa.md) |  |  | `ml-dsa` | `MlDsaParameters` | `MlDsaPublicKey` | `MlDsaPrivateKey` |
| [`SLH-DSA`](SlhDsa.md) |  |  | `slh-dsa` | `SlhDsaParameters` | `SlhDsaPublicKey` | `SlhDsaPrivateKey` |
| [`DSA`](Dsa.md) |  |  | `dsa` | `DsaKeyGenParams`, `DsaParameters` | `DsaPublicKey` | `DsaPrivateKey` |
| [`GOST3410`](Gost3410.md) | `GOST-3410`, `GOST-3410-94` |  | `gost3410` | `Gost3410KeyGenParams`, `Gost3410Parameters` | `Gost3410PublicKey` | `Gost3410PrivateKey` |

The names, aliases and OIDs are those of Bouncy Castle's `GeneratorUtilities`, but those of
Naccache-Stern and SM2, which it has no names for. The case of a name does not matter.

## Params

- Every row but `SM2`, `Ed25519`, `Ed448`, `X25519` and `X448` needs `init`, since none has params
  to assume: the size of an RSA key, the curve of an EC key, the group of DH and ElGamal, the domain
  of DSA and GOST R 34.10-94, the parameter set of ML-KEM, ML-DSA and SLH-DSA. `generate_by_name`
  gives `NotInitialized` there, so use `generate_by_name_with`, or `get_by_name`, `init` and
  `generate`.
- `SM2`, `Ed25519`, `Ed448`, `X25519` and `X448` have their curves fixed: `generate_by_name` gives a
  pair at once, and `init` refuses any params as `InvalidParams`.
- `DSA` and `GOST3410` take either a domain, or the size of a new one to generate at `init`, which
  takes a while; one `init` serves any number of pairs.
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
