# HKDF

A KDF turns a secret into key bytes. A shared secret from an agreement is not uniformly random, so it
is not a key yet, and one secret may need to become several keys. HKDF (RFC 5869) does both: it
extracts a pseudorandom key from the secret, and expands that into as many bytes as asked for. It
always runs over HMAC, so a row names only the digest.

With SHA-256. The `hkdf-sha256` feature of `tc_algo_v2` has the row.

```rust
use tc_algo_v2::params::HkdfParamsOwned;
use tc_algo_v2::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // The secret, a salt both sides know, and the label the protocol gives this key
    let secret = vec![0x5a; 32];
    let salt = vec![0xa5; 32];
    let info = b"example protocol v1: encryption key".to_vec();

    let mut kdf = algo.kdf().get_by_name("HKDF-SHA256")?;
    kdf.init(&HkdfParamsOwned::new(secret, salt, info))?;

    // The length is the one the key needs
    let mut key = [0; 32];
    kdf.generate_bytes(&mut key)?;

    Ok(())
}
```

## After an agreement

KDFs stand apart from agreements: which one follows which is up to the protocol, so nothing ties the
two together, and the caller passes the secret across. With the `dh` feature too:

```rust,ignore
let mut agreement = algo.agreement().get_by_name("DH")?;
agreement.init(alice.private())?;
let secret = agreement.calculate_agreement(bob.public())?;

let mut kdf = algo.kdf().get_by_name("HKDF-SHA256")?;
kdf.init(&HkdfParamsOwned::new(secret.as_bytes().to_vec(), salt, info))?;
```

`to_vec` leaves a second copy of the secret until the params are dropped. Both wipe themselves.

## Algorithms

| Name | OID | Feature | Most bytes |
|---|---|---|---|
| `HKDF-SHA256` | `1.2.840.113549.1.9.16.3.28` | `hkdf-sha256` | 8160 |
| `HKDF-SHA384` | `1.2.840.113549.1.9.16.3.29` | `hkdf-sha384` | 12240 |
| `HKDF-SHA512` | `1.2.840.113549.1.9.16.3.30` | `hkdf-sha512` | 16320 |

The case of a name does not matter. The OIDs are those of RFC 8619. Bouncy Castle has no factory of
KDFs, so the names are this crate's own.

## Params

The rows take an `HkdfParamsOwned`, in `tc_algo_v2::params`, and any other type is `InvalidParams`. It
wipes itself when dropped.

- `HkdfParamsOwned::new(ikm, salt, info)` extracts and expands. `ikm` is the secret. An empty `salt`
  stands for none, as in RFC 5869, though a salt is better where both sides can have one. `info` is
  the context, and different labels give independent keys from one secret.
- `HkdfParamsOwned::expand_only(prk, info)` skips the extract step, for a `prk` that is already a
  pseudorandom key. Do not use it on a shared secret from an agreement.

## Using it

- `generate_bytes` fills the buffer and returns its length. Keeping the key safe and wiping it is up
  to the caller.
- Each call goes on where the last one stopped, so the output can come in pieces.
- Past the most bytes in the table, 255 hashes, it gives `DataLength`, until a new `init`.
- It gives `NotInitialized` before an `init`.
- It is constant time with respect to the secret, as far as the digest is. The lengths are public.
