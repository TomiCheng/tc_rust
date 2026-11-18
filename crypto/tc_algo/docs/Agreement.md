# Agreements

In a key agreement, two sides each hold a key pair and send each other the public key. Each then
combines its own private key with the other's public key, and both arrive at one secret that
nobody watching can calculate. Unlike a KEM, both sides bring a key pair.

From two new pairs to one shared secret, with ECDH on P-256. The `ecdh` feature of `tc_algo` has
the row.

```rust
use tc_algo::params::generate::EcKeyGenParams;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let params = EcKeyGenParams::new("P-256");

    // Generate a pair for each side
    let alice = algo.key_pair_generator().generate_by_name_with("EC", &params)?;
    let bob = algo.key_pair_generator().generate_by_name_with("EC", &params)?;

    // Alice's private key with Bob's public key
    let mut agreement = algo.agreement().get_by_name("ECDH")?;
    agreement.init(alice.private())?;
    let mut alice_secret = vec![0; agreement.agreement_size()];
    agreement.calculate_agreement(bob.public(), &mut alice_secret)?;

    // Bob's private key with Alice's public key gives the same secret
    let mut agreement = algo.agreement().get_by_name("ECDH")?;
    agreement.init(bob.private())?;
    let mut bob_secret = vec![0; agreement.agreement_size()];
    agreement.calculate_agreement(alice.public(), &mut bob_secret)?;

    assert_eq!(alice_secret, bob_secret);
    Ok(())
}
```

## Algorithms

The names and OIDs are those of Bouncy Castle's `AgreementUtilities`, and the case of a name does
not matter.

- **[DH](Dh.md#agreement)**: Diffie-Hellman over a group such as those of RFC 3526 and RFC 7919,
  with the `dh` feature; `DIFFIEHELLMAN` finds it too.
- **ECDH** and **ECDHC**: Diffie-Hellman over an elliptic curve, ECDHC with the cofactor, with the
  `ecdh` feature; `ECCDH` finds ECDHC too.
- **ECMQV**: MQV over an elliptic curve, from a static and an ephemeral key on each side, with the
  `ecmqv` feature.
- **[X25519 and X448](X25519.md#agreement)**: the agreements of RFC 7748, with the `cfrg-curves`
  feature.
- **ECGOST3410**, **ECGOST3410-2012-256** and **ECGOST3410-2012-512**: VKO, the GOST R 34.10
  agreement, which hashes its secret with GOST R 34.11, with the `ecvko` feature;
  `GOST-3410-2001` finds the first too.
- **ECDH**, **ECCDH** or **ECMQV** **WITH** **SHA1**, **SHA224**, **SHA256**, **SHA384** or
  **SHA512** **KDF**, as `ECDHWITHSHA256KDF`: the EC agreements with the KDF of RFC 5753, which
  turns the secret into a key for a key-wrap algorithm. They need the feature of the agreement and
  of the digest, as `ecdh` and `sha`; `DHWITHSHA1KDF` finds `ECDHWITHSHA1KDF` too.

## Params

The params of `init` hold the private side, and `calculate_agreement` takes the other side's
public one. Any other type is `InvalidParams`, and so is a key on another curve than the private
key's: on the EC rows the curve comes from the keys.

- **DH**: a `DhPrivateKey`, and the other side's `DhPublicKey`.
- **ECDH** and **ECDHC**: an `EcPrivateKey`, and the other side's `EcPublicKey`.
- **ECMQV**: a `MqvPrivateParams` of the static and the ephemeral private keys, and the other
  side's `MqvPublicParams` of both public keys.
- **X25519** and **X448**: an `X25519PrivateKey` or `X448PrivateKey`, and the other side's public
  key of the same kind, from the `X25519` and `X448` key pair generators, which take no params.
- **VKO**: an `EcVkoParams` of the private key and the UKM, and the other side's `EcPublicKey`.
- **The KDF rows**: a `UkmParams` of the private params above and the UKM, or the private params
  alone for no UKM, and the other side's public key as above.

All these types are in `tc_algo::params`.

## Using it

- `get_by_name` and `get_by_oid` give an `Agreement`, which is an `Agreement` and an
  `AgreementInit` of `tc_agreement` with `AlgoError` for its errors, so code written for those
  traits takes it as it is.
- **The secret is not yet a key.** Its bytes are not uniformly random, so put them through a KDF
  before using them, or take a KDF row.
- **An agreement alone does not say who is on the other side.** Someone in the middle can run an
  agreement with each side, so authenticate the public keys, for instance with a signature or a
  certificate.
- A KDF row comes only from `get_with_kdf_by_name` and `get_with_kdf_by_oid`, Bouncy Castle's
  `GetBasicAgreementWithKdf`, which also take the `AlgorithmIdentifier` of the key-wrap algorithm,
  such as AES-128 Key Wrap. The secret is then a key of that algorithm's default size, and an
  algorithm without one is `InvalidParams`. `get_by_name` does not find a KDF row, and
  `get_with_kdf_by_name` does not find one without a KDF; both are `UnknownAgreement`.
- `calculate_agreement` writes the secret into a buffer of `agreement_size` bytes, and one too short
  is `DataLength`. The buffer is the caller's, and so is wiping it when the secret is done with,
  for instance with `tc_zeroize`.
- `agreement_size` is 0, and `calculate_agreement` gives `NotInitialized`, before an `init` that
  succeeded.
- A public key that the agreement refuses, such as one off the curve or outside the group, is
  `InvalidParams`.
