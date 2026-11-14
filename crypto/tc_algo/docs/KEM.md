# KEM

A key encapsulation mechanism gives two parties one secret, using only the public key of one of them.
The sender encapsulates against that public key, which gives a secret to keep and an encapsulation to
send. The receiver decapsulates that with the private key, and gets the same secret.

Nobody chooses the secret: it comes from the algorithm. Unlike DH, the sender needs no key pair, and
the two sides do different things. ML-KEM (FIPS 203) is also meant to withstand a quantum computer,
which RSA and DH are not.

From a new pair to one shared secret. The `ml-kem` feature of `tc_algo` has the rows.

```rust
use tc_algo::params::MlKemParameters;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // The receiver generates a pair, and publishes the public key
    let receiver = algo
        .key_pair_generator()
        .generate_by_name_with("ML-KEM", &MlKemParameters::ML_KEM_768)?;

    let name = "ML-KEM-768";

    // The sender keeps the secret, and sends the encapsulation
    let (encapsulation, sender_secret) = algo.kem().encapsulate_by_name(name, receiver.public())?;

    // The receiver gets the same secret from the encapsulation
    let receiver_secret =
        algo.kem()
            .decapsulate_by_name(name, receiver.private(), &encapsulation)?;

    assert_eq!(sender_secret, receiver_secret);
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

As in Bouncy Castle's `KemUtilities`, each row gives two objects: an `Encapsulator`, from
`get_encapsulator_by_name`, for the side that sends, and a `Decapsulator`, from
`get_decapsulator_by_name`, for the side that receives. They are the `KemEncapsulator` and
`KemDecapsulator` of `tc_kem`, with `init` taking any params, and write into buffers of
`encapsulation_length` and `secret_length` bytes. The helpers `encapsulate_by_name` and
`decapsulate_by_name` do all of it at once.

The encapsulator's `init` takes an `MlKemPublicKey` and the decapsulator's an `MlKemPrivateKey`,
both in `tc_algo::params`, of the parameter set of the row. The keys of a pair go straight in. Any
other type or parameter set is `InvalidParams`, and encapsulating or decapsulating before an `init`
that succeeded is `NotInitialized`.

## Using it

- **The encapsulation is not your message.** It only carries the secret, and is not secret itself.
  To send data, put the secret through a KDF such as HKDF, and encrypt the data with the key.
- **A changed encapsulation is not an error.** `decapsulate` then gives `Ok` with a different secret,
  as FIPS 203 requires, so as not to reveal whether it failed. It shows only when what follows fails,
  so authenticate the data with an AEAD cipher or a MAC.
- **It does not say who sent the encapsulation.** Anyone with the public key can make one, so
  authenticate the sender in some other way, for instance with a signature.
- An encapsulation of the wrong length is `DataLength`.
- The secret is a `Vec<u8>`, the caller's to wipe when it is done with, for instance with
  `tc_zeroize`.
- The encapsulation draws from the source of `DefaultAlgoBuilder::set_rand`.
