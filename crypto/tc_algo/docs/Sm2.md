# SM2

SM2 is the public-key cryptography of China's GM/T 0003, on the elliptic curve sm2p256v1. An SM2 key
pair is a private number `d` and the point `dG` on the curve. What the public key encrypts, only the
private key can decrypt; each encryption draws a new random number, so the same message gives a new
ciphertext each time.

The `sm2` feature of `tc_algo` has the rows. The curve is fixed: the keys are on sm2p256v1, and the
hash is SM3.

## Key pairs

A new pair needs no params:

```rust
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // Generate the pair
    let pair = algo.key_pair_generator().generate_by_name("SM2")?;

    // The public key goes to the other side; the private key stays here
    let _public = pair.public();
    let _private = pair.private();
    Ok(())
}
```

### Algorithms

| Name | OID | Feature | Params | Public key | Private key |
|---|---|---|---|---|---|
| `SM2` | none | `sm2` | none | `EcPublicKey<C>` on sm2p256v1 | `EcPrivateKey<C>` on sm2p256v1 |

Bouncy Castle makes SM2 keys with its EC generator and the domain of sm2p256v1; here the curve is the
row's, so the name is this crate's. The case of the name does not matter.

### Params

None: `generate_by_name` generates a pair, and `init` refuses any params as `InvalidParams`.

### Using it

- The keys are EC keys of `tc_ec_key` on sm2p256v1, made in constant time. They go straight into
  the SM2 rows of the cipher factory.
- The keys draw from the source of `DefaultAlgoBuilder::set_rand`.

## Encrypting

From a new pair to the decrypted message:

```rust
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let name = "SM2//C1C3C2";
    let message = b"attack at dawn";

    // Generate a pair
    let pair = algo.key_pair_generator().generate_by_name("SM2")?;

    // Encrypt with the public key
    let ciphertext = algo.cipher().encrypt_by_name(name, pair.public(), message)?;

    // Decrypt with the private key
    let plaintext = algo.cipher().decrypt_by_name(name, pair.private(), &ciphertext)?;

    assert_eq!(plaintext, message);
    Ok(())
}
```

### Algorithms

| Name | Aliases | OID | Feature | Order of the ciphertext |
|---|---|---|---|---|
| `SM2` | `C1C2C3` | none | `sm2` | C1 ‖ C2 ‖ C3 |
| `SM2//C1C3C2` | `C1C3C2` | none | `sm2` | C1 ‖ C3 ‖ C2 |

C1 is the point of the random number, C2 the message under the keystream and C3 the SM3 hash. The
standard of 2012 has C1C3C2; `SM2` alone is C1C2C3, Bouncy Castle's default, after an older draft.
The order takes the place of the padding: a name may give the mode as `NONE` or `ECB` and the order
by its alias, as `SM2/ECB/C1C3C2` does, and the case of a name does not matter. Bouncy Castle has
the engine but no name for it in `CipherUtilities`.

### Params

The rows take the public key of an `SM2` pair to encrypt and the private key to decrypt; the other
way round, or any other type, is `InvalidParams`.

### Using it

- **Both sides must use the same order.** C1C2C3 and C1C3C2 do not open each other's ciphertexts.
- The ciphertext is 97 bytes longer than the message: a point of 65 bytes and a hash of 32. A message
  of any length but zero goes in, and an empty one is `DataLength`.
- A changed ciphertext is `InvalidCiphertext`, and the hash is checked in fixed time.
- `update` keeps the input, and everything comes out of `finalize`.
- The random number of each encryption draws from the source of `DefaultAlgoBuilder::set_rand`.
