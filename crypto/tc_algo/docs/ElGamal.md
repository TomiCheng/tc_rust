# ElGamal

An ElGamal key pair is a public key anyone may hold and a private key only you hold, both in a group
of numbers modulo a prime `p`, the same groups as Diffie-Hellman's. What the public key encrypts,
only the private key can decrypt. Each encryption draws a new random number, so the same message
gives a new ciphertext each time.

The `elgamal` feature of `tc_algo` has the rows. The keys and the group are in `tc_algo::params`.

## Key pairs

From a group to a new pair:

```rust
use tc_algo::params::key::dh_groups::rfc3526_2048;
use tc_algo::params::{key::elgamal::ElGamalParameters, key::elgamal::ElGamalPrivateKey, key::elgamal::ElGamalPublicKey};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // The 2048-bit group of RFC 3526
    let group = rfc3526_2048();
    let params = ElGamalParameters::new(group.p().clone(), group.g().clone());

    // Generate the pair
    let pair = algo.key_pair_generator().generate_by_name_with("ELGAMAL", &params)?;

    // One key is an ElGamalPublicKey, the other an ElGamalPrivateKey
    let public = pair.public().as_any().downcast_ref::<ElGamalPublicKey>();
    let private = pair.private().as_any().downcast_ref::<ElGamalPrivateKey>();
    assert!(public.is_some() && private.is_some());
    Ok(())
}
```

### Algorithms

| Name | OID | Feature | Params | Public key | Private key |
|---|---|---|---|---|---|
| `ELGAMAL` | none | `elgamal` | `ElGamalParameters` | `ElGamalPublicKey` | `ElGamalPrivateKey` |

The name is that of Bouncy Castle's `GeneratorUtilities`, which gives it no OID. The case of the name
does not matter.

### Params

The row takes an `ElGamalParameters`, the prime `p` and the generator `g`, and any other type is
`InvalidParams`. A standard group, as those of RFC 3526 and RFC 7919 in `tc_dh_key`, saves
generating one, which is slow. `init` has `tc_elgamal` judge the group, so a bad one is
`InvalidParams` there.

### Using it

- `ELGAMAL` has no group to assume, so it needs `init`: `generate_by_name_with`, or `get_by_name`,
  `init` and `generate`. `generate_by_name` gives `NotInitialized`.
- Both sides of a message use keys of the same group.
- The keys draw from the source of `DefaultAlgoBuilder::set_rand`.

## Encrypting

From a new pair to the decrypted message, with OAEP over SHA-256:

```rust
use tc_algo::params::key::ElGamalParameters;
use tc_algo::params::key::dh_groups::rfc3526_2048;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let name = "ELGAMAL//OAEPWITHSHA256ANDMGF1PADDING";
    let message = b"attack at dawn";

    // Generate a pair
    let group = rfc3526_2048();
    let params = ElGamalParameters::new(group.p().clone(), group.g().clone());
    let pair = algo.key_pair_generator().generate_by_name_with("ELGAMAL", &params)?;

    // Encrypt with the public key
    let ciphertext = algo.cipher().encrypt_by_name(name, pair.public(), message)?;

    // Decrypt with the private key
    let plaintext = algo.cipher().decrypt_by_name(name, pair.private(), &ciphertext)?;

    assert_eq!(plaintext, message);
    Ok(())
}
```

### Algorithms

| Name | Padding | Most bytes, 2048-bit group |
|---|---|---|
| `ELGAMAL//OAEPWITHSHA256ANDMGF1PADDING` | OAEP over SHA-256 | 190 |
| `ELGAMAL//OAEPPADDING` | OAEP over SHA-1 | 214 |
| `ELGAMAL//PKCS1PADDING` | PKCS#1 v1.5 | 245 |
| `ELGAMAL` | none | 255, as a number below `p` |

There are OAEP rows over MD5, SHA-224, SHA-384 and SHA-512 too, and SHA-256 with MGF1 over SHA-1;
[Asymmetric ciphers](AsymCipher.md) lists them with their aliases. A name may give the mode as `NONE`
or `ECB`, and the case of a name does not matter. Bouncy Castle has no OID for them.

### Params

The rows take an `ElGamalPublicKey` to encrypt and an `ElGamalPrivateKey` to decrypt; the other way
round, or any other type, is `InvalidParams`.

### Using it

- **For new work use OAEP**, for the reason [RSA](Rsa.md#using-it-1) gives for PKCS#1 v1.5.
- The ciphertext is two numbers of the size of `p`, twice as long as a block of the message.
- One message is one block, so a longer one is `DataLength`. To encrypt more, encrypt a key for a
  symmetric cipher.
- `update` keeps the input, and everything comes out of `finalize`.
- The random number of each encryption, and the padding, draw from the source of
  `DefaultAlgoBuilder::set_rand`.
