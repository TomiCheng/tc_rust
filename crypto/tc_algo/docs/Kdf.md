# KDFs

A KDF turns a secret into key bytes. A shared secret from an agreement is not uniformly random, so
it is not a key yet, and one secret may need to become several keys, each with its own label. A KDF
is for secrets that are already hard to guess, but PBKDF2, which is slow on purpose, for passwords.

From a shared secret to a key, with HKDF over SHA-256. The `kdf` and `sha` features of
`tc_algo` have the row.

```rust
use tc_algo::params::kdf::HkdfParamsOwned;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

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

## Algorithms

Bouncy Castle has no factory of KDFs, so the names are this crate's own: the function, then the
digest or MAC underneath. The case of a name does not matter. A row is there when the feature of the
function and those of its digest or MAC are on.

`<DIGEST>` is the name of a [digest](Digest.md) row with the dash of `SHA-` dropped and a slash
turned into a dash, as the HMAC rows name it: SHA-256 gives `SHA256`, SHA-512/256 gives
`SHA512-256`, and SHA3-256 stays `SHA3-256`. `<MAC>` is the name of an HMAC or CMAC
[MAC](Mac.md) row, as `HMAC-SHA256` or `AESCMAC`. Each row also answers to the function followed by
any other name of its digest or MAC, as `HKDF-SHA-256` or `KDF-COUNTER-AES-CMAC`.

| Function | Name | Over | OIDs | Feature | Params |
|---|---|---|---|---|---|
| [HKDF](HKDF-SHA256.md), RFC 5869 | `HKDF-<DIGEST>`, as `HKDF-SHA256` | every digest but NONE, Haraka and the short-block ones below | RFC 8619, over SHA-256, -384 and -512 | `kdf` and the digest's | `HkdfParamsOwned` |
| KDF1, ISO 18033-2 | `KDF1-<DIGEST>`, as `KDF1-SHA256` | every digest but NONE and Haraka |  | `kdf` and the digest's | `KdfParamsOwned` |
| KDF2, ISO 18033-2 and ANSI X9.63 | `KDF2-<DIGEST>`, as `KDF2-SHA256` | every digest but NONE and Haraka |  | `kdf` and the digest's | `KdfParamsOwned` |
| One-step concatenation KDF, SP 800-56C | `CONCAT-<DIGEST>`, as `CONCAT-SHA256` | every digest but NONE and Haraka |  | `kdf` and the digest's | `KdfParamsOwned` |
| PBKDF2, RFC 8018 | `PBKDF2-HMAC-<DIGEST>`, as `PBKDF2-HMAC-SHA256` | every digest but NONE, Haraka and the short-block ones below |  | `pbe` and the digest's | `PbeParamsOwned` |
| SP 800-108, counter mode | `KDF-COUNTER-<MAC>`, as `KDF-COUNTER-HMAC-SHA256` | every HMAC and CMAC row |  | `kdf` and the MAC's | `KdfCounterParamsOwned` |
| SP 800-108, feedback mode | `KDF-FEEDBACK-<MAC>`, as `KDF-FEEDBACK-AESCMAC` | every HMAC and CMAC row |  | `kdf` and the MAC's | `KdfFeedbackParamsOwned` |
| SP 800-108, double-pipeline mode | `KDF-DOUBLEPIPELINE-<MAC>`, as `KDF-DOUBLEPIPELINE-HMAC-SHA256` | every HMAC and CMAC row |  | `kdf` and the MAC's | `KdfDoublePipelineParamsOwned` |

- HKDF and PBKDF2 run over HMAC, so they leave out the digests whose block is shorter than 16 bytes
  or than their output: `ASCON-HASH`, `ASCON-HASHA`, `ASCON-HASH256`, `ESCH-256`, `ESCH-384`,
  `ISAP`, `PHOTON-BEETLE` and `XOODYAK`. Every KDF leaves out `NONE`, `HARAKA-256` and
  `HARAKA-512`.
- HKDF is the one to use for new protocols.
- KDF1, KDF2 and the concatenation KDF run a digest over a counter, the secret and the context, for
  the formats and standards that name them.
- PBKDF2 is the KDF for a password, as CMS and PBES2 take it. [PBE](Pbe.md) gives the params of a
  cipher from a password instead.
- SP 800-108 runs a MAC over a counter and fixed input; HMAC and CMAC are the PRFs it names.
- `algorithms()` lists every row that is on, with its other names in `aliases()`.

The DH and ECDH key-encryption-key KDFs of RFC 2631 and RFC 5753 are not rows of their own: the
agreements with a KDF in [Agreement](Agreement.md) take them. Password hashes, such as scrypt and
Argon2, are not KDFs here either.

## Params

Each family takes its own params, all in `tc_algo::params`, and any other type is `InvalidParams`.
They wipe themselves when dropped.

- **HKDF**: an `HkdfParamsOwned` of the secret, a salt and the context, or of a pseudorandom key
  and the context alone with `expand_only`.
- **KDF1, KDF2 and concatenation**: a `KdfParamsOwned` of the secret, with the context or
  `OtherInfo` from `with_iv`.
- **PBKDF2**: a `PbeParamsOwned` of the password, already encoded, as UTF-8 for RFC 8018, the salt
  and the iteration count. A count of 0 is `InvalidParams` at `init`.
- **SP 800-108**: a `KdfCounterParamsOwned`, `KdfFeedbackParamsOwned` or
  `KdfDoublePipelineParamsOwned`, as the mode is, of the key of the MAC, the fixed input and the
  length of the counter in bits: 8, 16, 24 or 32, or none where the mode allows it. Any other length
  is `InvalidParams` at `init`.

## Using it

- `get_by_name` and `get_by_oid` give a `Kdf`, which is a `Kdf` and a `KdfInit` of `tc_kdf` with
  `AlgoError` for its errors, so code written for those traits takes it as it is.
- **Only PBKDF2 is for passwords.** The others run once, and a password needs to be slow to guess.
- `generate_bytes` fills the buffer and returns its length. Keeping the key safe and wiping it is up
  to the caller.
- HKDF and SP 800-108 go on where the last call stopped, so the output can come in pieces. KDF1,
  KDF2, the concatenation KDF and PBKDF2 start over at each call, as in Bouncy Castle, so take the
  whole output in one.
- Past the most bytes a function gives, such as 255 hashes for HKDF, it gives `DataLength`.
- It gives `NotInitialized` before an `init` that succeeded.
