# MACs

A MAC turns a message and a secret key into a short tag. Whoever has the same key can check the tag,
which shows that the message was not changed and that it came from someone with the key. Unlike a
digest it needs a key, and unlike a signature both sides hold the same one.

From a new key to a verified tag, with HMAC-SHA256. The `hmac-sha256` feature of `tc_algo` has
the rows.

```rust
use tc_algo::params::KeyLength;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let name = "HMAC-SHA256";
    let message = b"attack at dawn";

    // Generate a key
    let key = algo
        .key_generator()
        .generate_by_name_with("KEY", &KeyLength::new(32))?;

    // Calculate the tag
    let mut mac = algo.mac().get_by_name(name)?;
    mac.init(key.as_ref())?;
    mac.update(message)?;
    let tag = mac.finalize()?;

    // Verify the tag
    mac.update(message)?;
    assert!(mac.verify(&tag)?);

    Ok(())
}
```

The same with helpers, when the whole message is at hand:

```rust
use tc_algo::params::KeyLength;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let name = "HMAC-SHA256";
    let message = b"attack at dawn";

    let key = algo
        .key_generator()
        .generate_by_name_with("KEY", &KeyLength::new(32))?;
    let key = key.as_ref();

    let tag = algo.mac().calculate_by_name(name, key, message)?;
    assert!(algo.mac().verify_by_name(name, key, message, &tag)?);

    Ok(())
}
```

## Algorithms

The names and OIDs are those of Bouncy Castle's `MacUtilities`, and those it lacks follow its
provider. The case of a name does not matter. Key bytes use `x, y` for those lengths, `x..y` for a
range, and `..` for any length.

### HMAC

`HMAC-` and the name of a digest, for every [digest](Digest.md) whose feature is on, with the
`hmac` feature: `hmac-sha256` is `hmac` with `sha256`. The dash of `SHA-` goes, and a slash becomes a
dash, so SHA-512/256 gives `HMAC-SHA512-256`. `HMAC/` or `HMAC` before any name of the digest finds
it too, as `HMAC/SHA-256` and `HMACSHA256`. The key takes any length, and the tag is the size of the
digest. `NONE`, Haraka and the digests whose block is shorter than 16 bytes or than their digest,
such as Ascon and PHOTON-Beetle, have none.

| Name | OIDs |
|---|---|
| `HMAC-MD5` | `1.3.6.1.5.5.8.1.1` |
| `HMAC-SHA1` | `1.3.6.1.5.5.8.1.2`, `1.2.840.113549.2.7` |
| `HMAC-TIGER` | `1.3.6.1.5.5.8.1.3` |
| `HMAC-RIPEMD160` | `1.3.6.1.5.5.8.1.4` |
| `HMAC-SHA224` | `1.2.840.113549.2.8` |
| `HMAC-SHA256` | `1.2.840.113549.2.9` |
| `HMAC-SHA384` | `1.2.840.113549.2.10` |
| `HMAC-SHA512` | `1.2.840.113549.2.11` |
| `HMAC-SHA512-224` | `1.2.840.113549.2.12` |
| `HMAC-SHA512-256` | `1.2.840.113549.2.13` |
| `HMAC-SHA3-224` | `2.16.840.1.101.3.4.2.13` |
| `HMAC-SHA3-256` | `2.16.840.1.101.3.4.2.14` |
| `HMAC-SHA3-384` | `2.16.840.1.101.3.4.2.15` |
| `HMAC-SHA3-512` | `2.16.840.1.101.3.4.2.16` |
| `HMAC-GOST3411-2012-256` | `1.2.643.7.1.1.4.1` |
| `HMAC-GOST3411-2012-512` | `1.2.643.7.1.1.4.2` |

### Over a block cipher

Each needs the feature of its MAC and of its cipher, as `cbc-mac` with `des`. The key is the
cipher's.

| Name | Aliases | OIDs | Features | Tag bytes |
|---|---|---|---|---|
| `DESMAC` | `DES` |  | `cbc-mac`, `des` | 4 |
| `DESMAC64` | `DES64` |  | `cbc-mac`, `des` | 8 |
| `DESMAC/CFB8` | `DES/CFB8` |  | `cfb-mac`, `des` | 4 |
| `DESEDEMAC` | `DESEDE` | `1.2.840.113549.3.7` | `cbc-mac`, `desede` | 4 |
| `DESEDEMAC64` | `DESEDE64` |  | `cbc-mac`, `desede` | 8 |
| `DESEDEMAC64WITHISO7816-4PADDING` | `DESEDE64WITHISO7816-4PADDING`, `DESEDEISO9797ALG1MACWITHISO7816-4PADDING`, `DESEDEISO9797ALG1WITHISO7816-4PADDING` |  | `cbc-mac`, `desede` | 8 |
| `DESEDEMAC/CFB8` | `DESEDE/CFB8` |  | `cfb-mac`, `desede` | 4 |
| `SKIPJACKMAC` | `SKIPJACK` |  | `cbc-mac`, `skipjack` | 4 |
| `SKIPJACKMAC/CFB8` | `SKIPJACK/CFB8` |  | `cfb-mac`, `skipjack` | 4 |
| `IDEAMAC` | `IDEA` |  | `cbc-mac`, `idea` | 4 |
| `IDEAMAC/CFB8` | `IDEA/CFB8` |  | `cfb-mac`, `idea` | 4 |
| `RC2MAC` | `RC2` |  | `cbc-mac`, `rc2` | 4 |
| `RC2MAC/CFB8` | `RC2/CFB8` |  | `cfb-mac`, `rc2` | 4 |
| `RC5MAC` | `RC5` |  | `cbc-mac`, `rc5` | 4 |
| `RC5MAC/CFB8` | `RC5/CFB8` |  | `cfb-mac`, `rc5` | 4 |
| `<CIPHER>CMAC` | `<CIPHER>-CMAC` |  | `cmac`, the cipher's | the block |
| `<CIPHER>-GMAC` | `<CIPHER>GMAC` |  | `gmac`, the cipher's | 16 |

The `MAC` rows are CBC-MAC, and the `MAC/CFB8` rows CFB-MAC with a feedback of 8 bits, both with a
tag of half a block unless the name says 64 bits. The last block is padded with zeros, or with
ISO 7816-4 where the name says so.

CMAC is over `AES`, `ARIA`, `BLOWFISH`, `CAMELLIA`, `CAST5`, `CAST6`, `DES`, `DESEDE`, `GOST28147`,
`IDEA`, `NOEKEON`, `RC2`, `RC5`, `RC5-64`, `RC6`, `SEED`, `SERPENT`, `SKIPJACK`, `SM4`, `TEA`,
`TNEPRES`, `TWOFISH` and `XTEA`, the ciphers of a block of 8 or 16 bytes. GMAC is over those of 16:
`AES`, `ARIA`, `CAMELLIA`, `CAST6`, `NOEKEON`, `RC5-64`, `RC6`, `SEED`, `SERPENT`, `SM4`, `TNEPRES`
and `TWOFISH`.

### Others

| Name | Aliases | OIDs | Feature | Key bytes | Tag bytes |
|---|---|---|---|---|---|
| `ISO9797ALG3MAC` | `ISO9797ALG3`, `DESWITHISO9797`, `DESISO9797MAC` |  | `iso9797-alg3-mac` | 16, 24 | 8 |
| `ISO9797ALG3WITHISO7816-4PADDING` | `ISO9797ALG3MACWITHISO7816-4PADDING` |  | `iso9797-alg3-mac` | 16, 24 | 8 |
| `GOST28147MAC` | `GOST28147` |  | `gost28147-mac` | 32 | 4 |
| `VMPCMAC` | `VMPC`, `VMPC-MAC` |  | `vmpc-mac` | 16..64 | 20 |
| `SIPHASH-2-4` | `SIPHASH` |  | `siphash` | 16 | 8 |
| `SIPHASH-4-8` |  |  | `siphash` | 16 | 8 |
| `KMAC128` |  | `2.16.840.1.101.3.4.2.19` | `kmac` | .. | 32 |
| `KMAC256` |  | `2.16.840.1.101.3.4.2.20` | `kmac` | .. | 64 |
| `POLY1305` |  |  | `poly1305` | 32 | 16 |
| `SKEIN-MAC-<state>-<tag>` | `SKEINMAC-<state>-<tag>` |  | `skein-mac` | .. | the tag |

ISO 9797-1 algorithm 3 is the retail MAC over DES: CBC-MAC under the first key, and the last block
under the two-key or three-key triple DES. KMAC has an empty customization string. Skein-MAC is in
bits: 256 with a tag of 128, 160, 224 or 256; 512 with 128, 160, 224, 256, 384 or 512; 1024 with 384,
512 or 1024.

## Params

Any other type of params is `InvalidParams`, and so is an IV given to a MAC that takes none, or none
to one that needs it.

| MACs | Params |
|---|---|
| HMAC, CMAC, SipHash, KMAC, Poly1305, Skein-MAC | `KeyOwned` |
| CBC-MAC, CFB-MAC, ISO 9797-1 algorithm 3, GOST 28147 | `KeyOwned`, or `KeyWithIvOwned` with an IV of a block |
| GMAC | `KeyWithIvOwned`, the IV of GCM's |
| VMPC-MAC | `KeyWithIvOwned`, with an IV of 16..64 bytes |

A `KeyOwned` is a zero IV where the MAC takes one, as Bouncy Castle takes a `KeyParameter`. The
ciphers of their own params also take those, alone or in a `ParamsWithIvOwned`:
[`Rc2ParamsOwned`](Rc2.md) for RC2, [`Rc5ParamsOwned`](Rc5.md) for RC5 and RC5-64, and
[`Gost28147ParamsOwned`](Gost28147.md) for GOST 28147 and its MAC. A bare key gives them the defaults
of their pages. Every params type wipes the key when dropped.

The `KEY` key generator gives a `KeyOwned` of the length in a `KeyLength`, so it needs the helper with
params, `generate_by_name_with`. A key from elsewhere goes in with `KeyOwned::new(bytes)`.

## Using it

- `get_by_name` and `get_by_oid` give a `Mac`, which is a `Mac` and a `MacInit` of `tc_macs`
  with `AlgoError` for its errors, so code written for those traits takes it as it is.
- Check a tag with `verify`, or `verify_by_name` and `verify_by_oid`, never with `==`. They compare
  in constant time, whereas `==` stops at the first difference and tells an attacker how much of a
  forged tag is right.
- All of them give `Ok(false)` for a wrong tag, not an error, so look at the answer: a bare `?` on
  the call lets a forged message through.
- A message can come in pieces, over several calls of `update`.
- `finalize` and `verify` start the next message under the same key. `reset` discards the message so
  far and keeps the key.
- `update`, `finalize` and `verify` give `NotInitialized` before an `init` that succeeded.
