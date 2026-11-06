# RSA

An RSA key pair is a public key anyone may hold and a private key only you hold. Both share a modulus,
the product of two secret primes, and the size of that modulus in bits is the size of the key. What
the public key encrypts, only the private key can decrypt, and what the private key signs, anyone
with the public key can check.

The `rsa` feature of `tc_algo_v2` has the rows. The random source that the params ask for comes from
`rand` and `rand_core`.

## Key pairs

From the params to a new pair:

```rust
use rand::rngs::SysRng;
use rand_core::UnwrapErr;
use tc_algo_v2::params::{RsaKey, RsaKeyGenerationParamsOwned, RsaKeyParams};
use tc_algo_v2::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // A 2048-bit key
    let params = RsaKeyGenerationParamsOwned::new(UnwrapErr(SysRng)).with_strength(2048);

    // Generate the pair
    let pair = algo.key_pair_generator().generate_by_name_with("RSA", &params)?;

    // Each key is an RsaKey
    let public = pair.public().as_any().downcast_ref::<RsaKey>().expect("an RsaKey");
    let private = pair.private().as_any().downcast_ref::<RsaKey>().expect("an RsaKey");

    assert_eq!(public.modulus(), private.modulus());
    Ok(())
}
```

### Algorithms

| Name | OID | Feature | Params |
|---|---|---|---|
| `RSA` | `1.2.840.113549.1.1.1` | `rsa` | `RsaKeyGenerationParamsOwned` |

The case of the name does not matter.

### Params

The row takes an `RsaKeyGenerationParamsOwned`, and any other type is `InvalidParams`. It starts at
the defaults of Bouncy Castle, and the `with_` methods change them:

| Method | Default | Must be |
|---|---|---|
| `with_strength` | 2048 | at least 16 bits, but use at least 2048 |
| `with_public_exponent` | 65537 | odd, and at least 3 |
| `with_certainty` | 100 | at least 1 |

`init` has `tc_rsa` judge these, so a bad value is `InvalidParams` there and not at `generate`. `tc_rsa`
takes sizes far too small to be safe, so choosing a safe one is up to the caller.

**The random source in the params goes unused.** `new` asks for one, but `init` can only read the
params, so the keys draw from the source of `DefaultAlgoBuilder::set_rand`, which by default is the
operating system's.

### Using it

- `RSA` has no size to assume, so it needs `init`. Use `generate_by_name_with` or
  `generate_by_oid_with`, or `get_by_name`, `init` and `generate`. `generate_by_name` and
  `generate_by_oid` do not call `init`, so with `RSA` they give `NotInitialized`.
- The public key is the modulus and the public exponent. The private key has the CRT values too.
  `RsaKey` wipes itself when dropped, and has no `Debug`, which would show the private values.
- Generating a key is slow, and the larger the key, the slower. Its time varies with how many
  candidates it tries for the primes.
- Each `get_by_name` asks the function given to `set_rand` for a source anew. A function that gives
  the same seed each time makes every generator generate the same key.

## Encrypting

From a new pair to the decrypted message, with OAEP over SHA-256. The keys of a pair go straight in
as params:

```rust
use rand::rngs::SysRng;
use rand_core::UnwrapErr;
use tc_algo_v2::params::RsaKeyGenerationParamsOwned;
use tc_algo_v2::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let name = "RSA//OAEPWITHSHA256ANDMGF1PADDING";
    let message = b"attack at dawn";

    // Generate a pair
    let params = RsaKeyGenerationParamsOwned::new(UnwrapErr(SysRng)).with_strength(2048);
    let pair = algo.key_pair_generator().generate_by_name_with("RSA", &params)?;

    // Encrypt with the public key
    let ciphertext = algo.cipher().encrypt_by_name(name, pair.public(), message)?;

    // Decrypt with the private key
    let plaintext = algo.cipher().decrypt_by_name(name, pair.private(), &ciphertext)?;

    assert_eq!(plaintext, message);
    Ok(())
}
```

### Algorithms

| Name | OID | Padding | Most bytes, 2048-bit key |
|---|---|---|---|
| `RSA//OAEPWITHSHA256ANDMGF1PADDING` | none | OAEP over SHA-256 | 190 |
| `RSA//OAEPPADDING` | `1.2.840.113549.1.1.7` | OAEP over SHA-1 | 214 |
| `RSA//PKCS1PADDING` | `1.2.840.113549.1.1.1` | PKCS#1 v1.5 | 245 |
| `RSA` | none | none | 256, as a number below the modulus |

All of them need the `rsa` feature, and the case of a name does not matter. A name may give the mode
as `NONE` or `ECB`, as `RSA/ECB/PKCS1PADDING` does. These find the same rows too:

- `PKCS1` for `PKCS1PADDING`.
- `OAEP`, `OAEPWITHSHA1ANDMGF1PADDING` and `OAEPWITHSHA-1ANDMGF1PADDING` for `OAEPPADDING`.
- `OAEPWITHSHA-256ANDMGF1PADDING`, `OAEPWITHSHA256ANDMGF1WITHSHA256PADDING` and
  `OAEPWITHSHA-256ANDMGF1WITHSHA-256PADDING` for `OAEPWITHSHA256ANDMGF1PADDING`.
- `NOPADDING` for no padding.

### Params

The rows take an `RsaKey`, and any other type is `InvalidParams`. As in Bouncy Castle, either key
works in either direction, so it is up to the caller to encrypt with the public one.

### Using it

- **For new work use OAEP.** PKCS#1 v1.5 reports a bad padding as an error, and an attacker who can
  see that fail can use it to decrypt a ciphertext, which is Bleichenbacher's attack.
- **`RSA` without padding is not safe to use on its own.** Equal messages give equal ciphertexts, and
  it is for callers who do their own encoding. It gives back a whole block, with zeros in front of
  a shorter message.
- One message is one block, so a longer one is `DataLength`. To encrypt more, encrypt a key for a
  symmetric cipher, and the message with that.
- `update` keeps the input, and everything comes out of `finalize`.
- A changed ciphertext is `InvalidCiphertext` with a padding, but `RSA` without one cannot tell, and
  gives back a wrong block.
- The padding and the blinding draw from the source of `DefaultAlgoBuilder::set_rand`.

## Signing

From a new pair to a verified signature, with PKCS#1 v1.5 over SHA-256. The keys of a pair go straight
in as params:

```rust
use rand::rngs::SysRng;
use rand_core::UnwrapErr;
use tc_algo_v2::params::RsaKeyGenerationParamsOwned;
use tc_algo_v2::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let name = "SHA-256withRSA";
    let message = b"attack at dawn";

    // Generate a pair
    let params = RsaKeyGenerationParamsOwned::new(UnwrapErr(SysRng)).with_strength(2048);
    let pair = algo.key_pair_generator().generate_by_name_with("RSA", &params)?;

    // Sign with the private key
    let mut signer = algo.signer().get_by_name(name)?;
    signer.init(pair.private())?;
    signer.update(message)?;
    let signature = signer.sign()?;

    // Verify with the public key
    let mut verifier = algo.signer().get_by_name(name)?;
    verifier.init(pair.public())?;
    verifier.update(message)?;
    assert!(verifier.verify_signature(&signature)?);

    Ok(())
}
```

### Algorithms

| Name | OID | Feature | Signature bytes |
|---|---|---|---|
| `SHA-256withRSA` | `1.2.840.113549.1.1.11` | `rsa` | the size of the modulus |

`SHA256withRSA`, `SHA256withRSAEncryption` and `SHA-256withRSAEncryption` find it too, and the case of
a name does not matter.

### Params

The row takes an `RsaKey`, and any other type is `InvalidParams`. The key tells the direction: a
private key signs, and a public key verifies.

### Using it

- **Look at the answer of `verify_signature`.** A wrong signature gives `Ok(false)`, not an error, so
  a bare `?` on the call lets a forged message through.
- A message can come in pieces, over several calls of `update`.
- `sign` gives the signature in a `Vec`. `generate_signature` writes it into a buffer of
  `max_signature_size` bytes, and one too short is `DataLength`.
- `sign`, `generate_signature` and `verify_signature` start the next message under the same key.
  `reset` discards the message so far.
- `update`, `generate_signature` and `verify_signature` give `NotInitialized` before an `init` that
  succeeded. So do `generate_signature` with a public key and `verify_signature` with a private one.
- PKCS#1 v1.5 gives the same signature for the same key and message. The blinding draws from the
  source of `DefaultAlgoBuilder::set_rand`.
