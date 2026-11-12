# Key generation

`algo.key_generator()` makes secret keys, for ciphers and MACs; `algo.key_pair_generator()` makes
key pairs, a public key and a private one.

```rust
use tc_algo::params::{KeyOwned, RsaKeyGenParams};
use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};

let algo = DefaultAlgoBuilder::default().build();

// A secret key
let key = algo.key_generator().generate_by_name("AES256")?;
let key = key.as_any().downcast_ref::<KeyOwned>().expect("a KeyOwned");

// A key pair
let pair = algo
    .key_pair_generator()
    .generate_by_name_with("RSA", &RsaKeyGenParams::new(2048))?;
```

## Secret keys

- `AES128`, `AES192`, `AES256`: an AES key of that many bits
- `KEY`: a key of any length, given in `KeyLength`

Each gives a `KeyOwned`. The `aes` feature has the rows.

## Key pairs

- `RSA`, with `RsaKeyGenParams`: an `RsaKey` each; see [RSA](Rsa.md)
- `DH`, also `DIFFIEHELLMAN`, with the group in `DhParameters`: a `DhPublicKey` and a
  `DhPrivateKey`; see [Diffie-Hellman](Dh.md)
- `ML-KEM`, with `MlKemParameters`, such as `MlKemParameters::ML_KEM_768`: an `MlKemPublicKey` and
  an `MlKemPrivateKey`; see [KEM](KEM.md)

## Using it

- `generate_by_name` uses the params the row has by default; `generate_by_name_with` takes
  them. `by_oid` does the same by OID.
- `get_by_name` gives a generator to `init` once and `generate` from many times.
- Keys come back as `&dyn Params`; `as_any().downcast_ref` gives the type above.
- The randomness is the system's, unless the builder's `set_rand` gives another source.
