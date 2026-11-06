# KEM

A key encapsulation mechanism gives two parties one secret, using only the public key of one of them.
The sender encapsulates against that public key, which gives a secret to keep and an encapsulation to
send. The receiver decapsulates that with the private key, and gets the same secret.

Nobody chooses the secret: it comes from the algorithm. Unlike DH, the sender needs no key pair, and
the two sides do different things. ML-KEM (FIPS 203) is also meant to withstand a quantum computer,
which RSA and DH are not.

From a new pair to one shared secret. The `ml-kem` feature of `tc_algo_v2` has the rows.

```rust
use tc_algo_v2::params::MlKemParameters;
use tc_algo_v2::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // The receiver generates a pair, and publishes the public key
    let receiver = algo
        .key_pair_generator()
        .generate_by_name_with("ML-KEM", &MlKemParameters::ML_KEM_768)?;

    let kem = algo.kem().get_by_name("ML-KEM-768")?;

    // The sender keeps the secret, and sends the encapsulation
    let (encapsulation, sender_secret) = kem.encapsulate(receiver.public())?;

    // The receiver gets the same secret from the encapsulation
    let receiver_secret = kem.decapsulate(receiver.private(), &encapsulation)?;

    assert_eq!(sender_secret.as_bytes(), receiver_secret.as_bytes());
    Ok(())
}
```

## Algorithms

| Name | OID | Feature | Encapsulation bytes | Secret bytes |
|---|---|---|---|---|
| `ML-KEM-512` | `2.16.840.1.101.3.4.4.1` | `ml-kem` | 768 | 32 |
| `ML-KEM-768` | `2.16.840.1.101.3.4.4.2` | `ml-kem` | 1088 | 32 |
| `ML-KEM-1024` | `2.16.840.1.101.3.4.4.3` | `ml-kem` | 1568 | 32 |

The case of a name does not matter. The names and OIDs are those of Bouncy Castle.

## Key pairs

The key pair generator is one row, `ML-KEM`, also with the `ml-kem` feature. It takes an
`MlKemParameters`, and any other type is `InvalidParams`:

| Parameter set | Row of the KEM |
|---|---|
| `MlKemParameters::ML_KEM_512` | `ML-KEM-512` |
| `MlKemParameters::ML_KEM_768` | `ML-KEM-768` |
| `MlKemParameters::ML_KEM_1024` | `ML-KEM-1024` |

There is no default, so `generate_by_name` and `generate_by_oid`, which do not call `init`, give
`NotInitialized`. The keys draw from the source of `DefaultAlgoBuilder::set_rand`.

## Params

`encapsulate` takes an `MlKemPublicKey` and `decapsulate` an `MlKemPrivateKey`, both in
`tc_algo_v2::params`, of the parameter set of the row. The keys of a pair go straight in. Any other
type or parameter set is `InvalidParams`.

## Using it

- **The encapsulation is not your message.** It only carries the secret, and is not secret itself.
  To send data, put the secret through a KDF such as HKDF, and encrypt the data with the key.
- **A changed encapsulation is not an error.** `decapsulate` then gives `Ok` with a different secret,
  as FIPS 203 requires, so as not to reveal whether it failed. It shows only when what follows fails,
  so authenticate the data with an AEAD cipher or a MAC.
- **It does not say who sent the encapsulation.** Anyone with the public key can make one, so
  authenticate the sender in some other way, for instance with a signature.
- An encapsulation of the wrong length is `DataLength`.
- The secret is a `SharedSecret`, from `tc_algo_v2::agreement`. `as_bytes` reads it, it wipes itself
  when dropped, and it has no `Clone`, `==` or `Debug`.
- The encapsulation draws from the source of `DefaultAlgoBuilder::set_rand`.
