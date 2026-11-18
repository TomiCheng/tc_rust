# RSA

An RSA key pair is a public key anyone may hold and a private key only you hold. Both share a modulus,
the product of two secret primes, and the size of that modulus in bits is the size of the key. What
the public key encrypts, only the private key can decrypt, and what the private key signs, anyone
with the public key can check.

The `rsa` feature of `tc_algo` has the rows.

## Key pairs

From the params to a new pair:

```rust
use tc_algo::params::{RsaKey, RsaKeyGenParams, RsaKeyParams};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // A 2048-bit key
    let params = RsaKeyGenParams::new(2048);

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

| Name | OID | Feature | Params | Public key | Private key |
|---|---|---|---|---|---|
| `RSA` | `1.2.840.113549.1.1.1` | `rsa` | `RsaKeyGenParams` | `RsaKey` | `RsaKey` |

The case of the name does not matter.

### Params

The row takes an `RsaKeyGenParams`, in `tc_algo::params`, and any other type is `InvalidParams`.
`new` takes the size of the key, as it has no default. The rest start at the defaults of Bouncy
Castle, and the `with_` methods change them:

| Set by | Default | Must be |
|---|---|---|
| `new` | none | at least 16 bits, but use at least 2048 |
| `with_public_exponent` | 65537 | odd, and at least 3 |
| `with_certainty` | 100 | at least 1 |

`init` has `tc_rsa` judge these, so a bad value is `InvalidParams` there and not at `generate`. `tc_rsa`
takes sizes far too small to be safe, so choosing a safe one is up to the caller.

The keys draw from the source of `DefaultAlgoBuilder::set_rand`, which by default is the operating
system's.

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
use tc_algo::params::RsaKeyGenParams;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let name = "RSA//OAEPWITHSHA256ANDMGF1PADDING";
    let message = b"attack at dawn";

    // Generate a pair
    let params = RsaKeyGenParams::new(2048);
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
use tc_algo::params::RsaKeyGenParams;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let name = "SHA-256withRSA";
    let message = b"attack at dawn";

    // Generate a pair
    let params = RsaKeyGenParams::new(2048);
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

The names and OIDs are those of Bouncy Castle's `SignerUtilities`, and the case of a name does not
matter. A row over a digest needs `rsa` and the digest's feature, as `rsa` and `sha`. The
signature is the size of the modulus.

| Name | Aliases | OIDs | Features |
|---|---|---|---|
| `MD2withRSA` | `MD2WITHRSAENCRYPTION` | `1.2.840.113549.1.1.2` | `rsa` and `md` |
| `MD4withRSA` | `MD4WITHRSAENCRYPTION` | `1.2.840.113549.1.1.3`, `1.3.14.3.2.2`, `1.3.14.3.2.4` | `rsa` and `md` |
| `MD5withRSA` | `MD5WITHRSAENCRYPTION` | `1.2.840.113549.1.1.4`, `1.3.14.3.2.3` | `rsa` and `md` |
| `SHA-1withRSA` | `SHA1WITHRSA`, `SHA1WITHRSAENCRYPTION` | `1.2.840.113549.1.1.5`, `1.3.14.3.2.29` | `rsa` and `sha` |
| `SHA-224withRSA` | `SHA224WITHRSA`, `SHA224WITHRSAENCRYPTION` | `1.2.840.113549.1.1.14` | `rsa` and `sha` |
| `SHA-256withRSA` | `SHA256WITHRSA`, `SHA256WITHRSAENCRYPTION` | `1.2.840.113549.1.1.11` | `rsa` and `sha` |
| `SHA-384withRSA` | `SHA384WITHRSA`, `SHA384WITHRSAENCRYPTION` | `1.2.840.113549.1.1.12` | `rsa` and `sha` |
| `SHA-512withRSA` | `SHA512WITHRSA`, `SHA512WITHRSAENCRYPTION` | `1.2.840.113549.1.1.13` | `rsa` and `sha` |
| `SHA-512(224)withRSA` | `SHA512(224)WITHRSA`, `SHA-512/224WITHRSA` | `1.2.840.113549.1.1.15` | `rsa` and `sha` |
| `SHA-512(256)withRSA` | `SHA512(256)WITHRSA`, `SHA-512/256WITHRSA` | `1.2.840.113549.1.1.16` | `rsa` and `sha` |
| `SHA3-224withRSA` | `SHA3-224WITHRSAENCRYPTION` | `2.16.840.1.101.3.4.3.13` | `rsa` and `keccak` |
| `SHA3-256withRSA` | `SHA3-256WITHRSAENCRYPTION` | `2.16.840.1.101.3.4.3.14` | `rsa` and `keccak` |
| `SHA3-384withRSA` | `SHA3-384WITHRSAENCRYPTION` | `2.16.840.1.101.3.4.3.15` | `rsa` and `keccak` |
| `SHA3-512withRSA` | `SHA3-512WITHRSAENCRYPTION` | `2.16.840.1.101.3.4.3.16` | `rsa` and `keccak` |
| `RIPEMD128withRSA` | `RIPEMD128WITHRSAENCRYPTION` | `1.3.36.3.3.1.3` | `rsa` and `ripemd` |
| `RIPEMD160withRSA` | `RIPEMD160WITHRSAENCRYPTION` | `1.3.36.3.3.1.2` | `rsa` and `ripemd` |
| `RIPEMD256withRSA` | `RIPEMD256WITHRSAENCRYPTION` | `1.3.36.3.3.1.4` | `rsa` and `ripemd` |
| `<DIGEST>withRSAandMGF1`, for every digest but `NONE` | `<DIGEST>WITHRSA/PSS`, `<DIGEST>WITHRSASSA-PSS` |  | `rsa` and the digest's |
| `<DIGEST>withRSA/X9.31`, for the digests below |  |  | `rsa` and the digest's |
| `<DIGEST>withRSA/ISO9796-2`, for the digests below |  |  | `rsa` and the digest's |
| `PSSwithRSA` | `RSASSA-PSS`, `RSAPSS` | `1.2.840.113549.1.1.10` | `rsa` and `sha` |
| `RAWRSASSA-PSS` | `RAWRSAPSS`, `NONEWITHRSAPSS`, `NONEWITHRSASSA-PSS` |  | `rsa` and `sha` |
| `NONEwithRSA` | `RSA`, `RSAWITHNONE`, `RAWRSA` |  | `rsa` |

`<DIGEST>` is any name of the digest, so `SHA256withRSA` and `SHA-256WITHRSA` are the same row.

- **PKCS#1 v1.5**, the `withRSA` rows: deterministic, the same signature for the same key and
  message. Its DigestInfo names the digest, so it is for the digests above alone.
- **PSS**, the `withRSAandMGF1` rows: MGF1 over the same digest and a salt of its size, as Bouncy
  Castle builds it, so a new signature each time. `PSSwithRSA` is PSS over SHA-1, Bouncy Castle's
  default for the OID of RSASSA-PSS.
- **X9.31**: for SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, RIPEMD128,
  RIPEMD160 and WHIRLPOOL, the digests with a trailer.
- **ISO 9796-2**: for SHA-1, MD5 and RIPEMD160, with the implicit trailer, as Bouncy Castle builds
  it.
- **`NONEwithRSA`** signs what it is given, as a hash with its DigestInfo, and **`RAWRSASSA-PSS`** a
  SHA-1 hash: they are for a hash made elsewhere.

### Params

Every row takes an `RsaKey`, and any other type is `InvalidParams`. The key tells the direction: a
private key signs, and a public key verifies.

### Using it

- The engine is blinded, as Bouncy Castle builds it, and the blinding draws from the source of
  `DefaultAlgoBuilder::set_rand`.
- A key too small for the digest, as for PSS over SHA-512 with a modulus of 1024 bits, is
  `InvalidParams`.
- The rest is common to every signer: [Signers](Signer.md#using-it).
