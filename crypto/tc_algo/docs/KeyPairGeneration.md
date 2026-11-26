# Key pair generation

A key pair is a public key, to give to anyone, and a private key, to keep. What the public key
encrypts or checks, only the private key decrypts or signs; two sides with a pair each can agree
on a secret. `algo.key_pair_generator()` makes the pair from a random source. For one secret key
that both sides share, see [Key generation](KeyGeneration.md).

From a name and its params to a new pair, and the pair straight into a cipher:

```rust
use tc_algo::params::generate::RsaKeyGenParams;
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

Import key-pair generation parameters from `tc_algo::params::generate`. Fixed-curve rows
(`SM2`, `Ed25519`, `Ed448`, `X25519`, and `X448`) take no parameters: `generate_by_name`
generates a pair immediately, and calling `init` returns `InvalidParams`. Every other row
has no default parameters and returns `NotInitialized` until `init` succeeds; invalid
parameters return `InvalidParams` during `init` (except pre-built `DsaParameters` and
`Gost3410Parameters`, which are validated during `generate`).

- [`RsaKeyGenParams`](KeyPairGeneration/RsaKeyGenParams.md): Modulus size in bits, with
  optional public exponent and prime test certainty, for `RSA`.
- [`EcKeyGenParams`](KeyPairGeneration/EcKeyGenParams.md): Named curve for `EC`.
- [`DhParameters`](KeyPairGeneration/DhParameters.md): Diffie-Hellman group for `DH`.
- [`MlKemParameters`](KeyPairGeneration/MlKemParameters.md): Parameter set for `ML-KEM`.
- [`ElGamalParameters`](KeyPairGeneration/ElGamalParameters.md): Group parameters for `ELGAMAL`.
- [`NaccacheSternKeyGenerationParams`](KeyPairGeneration/NaccacheSternKeyGenerationParams.md): Modulus size, certainty, and
  small-prime count for `NACCACHESTERN`.
- [`MlDsaParameters`](KeyPairGeneration/MlDsaParameters.md): Parameter set for `ML-DSA`.
- [`SlhDsaParameters`](KeyPairGeneration/SlhDsaParameters.md): Parameter set for `SLH-DSA`.
- [`DsaKeyGenParams`](KeyPairGeneration/DsaKeyGenParams.md), [`DsaParameters`](KeyPairGeneration/DsaKeyGenParams.md#a-domain-in-hand): Parameters to generate a new
  domain during `init` (which is slow and can be reused for many pairs) or an existing
  domain, for `DSA`.
- [`Gost3410KeyGenParams`](KeyPairGeneration/Gost3410KeyGenParams.md), [`Gost3410Parameters`](KeyPairGeneration/Gost3410KeyGenParams.md#a-domain-in-hand): Parameters
  to generate a new domain during `init` or an existing domain, for `GOST3410`.

## Returns

Every generator returns a `KeyPair` of two `Box<dyn Params>` whose concrete types match the Public
key and Private key columns. Import the key types from `tc_algo::params::key`. You can pass the
keys directly to an algorithm that accepts them (a cipher, a signer, an agreement or a KEM), or
downcast them with `as_any().downcast_ref::<T>()` to read their values. Private keys wipe their
secret values when dropped.

- [`RsaKey`](KeyPair/RsaKey.md): Both keys; `modulus()` and `exponent()`
  through `RsaKeyParams`. The public key is `RsaKey::Core` with `e`, the private key `RsaKey::Crt`
  with `d` and its CRT values.
- [`EcPublicKey<C>`, `EcPrivateKey<C>`](KeyPairGeneration/EcKeyGenParams.md): The point `q()` and
  the scalar `d()`, with the base point `g()`, on the curve type `C`; the curve aliases name `C` and
  the keys, such as `EcSecp256r1PublicKey`.
- [`DhPublicKey`, `DhPrivateKey`](KeyPairGeneration/DhParameters.md): The values `y()` and `x()`,
  with the group `params()`.
- [`MlKemPublicKey`, `MlKemPrivateKey`](KeyPairGeneration/MlKemParameters.md): The FIPS 203
  `encoding()` and the set `params()`; the private key also has `seed()` and `public_key()`.
- [`ElGamalPublicKey`, `ElGamalPrivateKey`](KeyPairGeneration/ElGamalParameters.md): The values
  `y()` and `x()`, with the group `params()`.
- [`NaccacheSternPublicKey`, `NaccacheSternPrivateKey`](KeyPairGeneration/NaccacheSternKeyGenerationParams.md):
  `g()`, `n()` and `lower_sigma_bound()`; the private key has `public_key()`, `small_primes()` and
  `phi_n()`.
- [`Sm2PublicKey`, `Sm2PrivateKey`](Sm2.md): `EcPublicKey` and `EcPrivateKey` on `sm2p256v1`.
- [`Ed25519PublicKey`, `Ed25519PrivateKey`](EdDSA.md), [`Ed448PublicKey`, `Ed448PrivateKey`](EdDSA.md):
  The encoded `a()` and `k()` of RFC 8032; the private key also has `generate_public_key()`.
- [`X25519PublicKey`, `X25519PrivateKey`](X25519.md), [`X448PublicKey`, `X448PrivateKey`](X25519.md):
  The encoded `u()` and `k()` of RFC 7748; the private key also has `generate_public_key()`.
- [`MlDsaPublicKey`, `MlDsaPrivateKey`](KeyPairGeneration/MlDsaParameters.md): The FIPS 204
  `encoding()` and the set `params()`; the private key also has `seed()` and `public_key()`.
- [`SlhDsaPublicKey`, `SlhDsaPrivateKey`](KeyPairGeneration/SlhDsaParameters.md): The FIPS 205
  `encoding()` and the set `params()`; the private key also has `public_key()`.
- [`DsaPublicKey`, `DsaPrivateKey`](KeyPairGeneration/DsaKeyGenParams.md): The values `y()` and
  `x()`, with the domain `params()`.
- [`Gost3410PublicKey`, `Gost3410PrivateKey`](KeyPairGeneration/Gost3410KeyGenParams.md): The
  values `y()` and `x()`, with the domain `params()`.

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
