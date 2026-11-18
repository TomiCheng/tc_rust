# MACs

A MAC turns a message and a secret key into a short tag. Whoever has the same key can check the tag,
which shows that the message was not changed and that it came from someone with the key. Unlike a
digest it needs a key, and unlike a signature both sides hold the same one.

From a new key to a verified tag, with HMAC-SHA256. The `macs` and `sha` feature of `tc_algo` has
the rows.

```rust
use tc_algo::params::generate::KeyLength;
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
use tc_algo::params::generate::KeyLength;
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
`macs` feature, and the digest's feature, as `macs` and `sha` for `HMAC-SHA256`. The dash of `SHA-` goes, and a slash becomes a
dash, so SHA-512/256 gives `HMAC-SHA512-256`. `HMAC/` or `HMAC` before any name of the digest finds
it too, as `HMAC/SHA-256` and `HMACSHA256`. The key takes any length, and the tag is the size of the
digest. `NONE`, Haraka and the digests whose block is shorter than 16 bytes or than their digest,
such as Ascon and PHOTON-Beetle, have none.

| Name | Aliases | OIDs | Features | Params | Tag bytes |
|---|---|---|---|---|---|
| `HMAC-MD5` | `HMAC/MD5`, `HMACMD5` | `1.3.6.1.5.5.8.1.1` | `macs` and `md` | `KeyOwned` | 16 |
| `HMAC-SHA1` | `HMAC-SHA-1`, `HMAC/SHA-1`, `HMACSHA-1`, `HMAC/SHA1`, `HMACSHA1` | `1.3.6.1.5.5.8.1.2`, `1.2.840.113549.2.7` | `macs` and `sha` | `KeyOwned` | 20 |
| `HMAC-TIGER` | `HMAC/TIGER`, `HMACTIGER` | `1.3.6.1.5.5.8.1.3` | `macs` and `misc-digest` | `KeyOwned` | 24 |
| `HMAC-RIPEMD160` | `HMAC/RIPEMD160`, `HMACRIPEMD160`, `HMAC-RIPEMD-160`, `HMAC/RIPEMD-160`, `HMACRIPEMD-160` | `1.3.6.1.5.5.8.1.4` | `macs` and `ripemd` | `KeyOwned` | 20 |
| `HMAC-SHA224` | `HMAC-SHA-224`, `HMAC/SHA-224`, `HMACSHA-224`, `HMAC/SHA224`, `HMACSHA224` | `1.2.840.113549.2.8` | `macs` and `sha` | `KeyOwned` | 28 |
| `HMAC-SHA256` | `HMAC-SHA-256`, `HMAC/SHA-256`, `HMACSHA-256`, `HMAC/SHA256`, `HMACSHA256` | `1.2.840.113549.2.9` | `macs` and `sha` | `KeyOwned` | 32 |
| `HMAC-SHA384` | `HMAC-SHA-384`, `HMAC/SHA-384`, `HMACSHA-384`, `HMAC/SHA384`, `HMACSHA384` | `1.2.840.113549.2.10` | `macs` and `sha` | `KeyOwned` | 48 |
| `HMAC-SHA512` | `HMAC-SHA-512`, `HMAC/SHA-512`, `HMACSHA-512`, `HMAC/SHA512`, `HMACSHA512` | `1.2.840.113549.2.11` | `macs` and `sha` | `KeyOwned` | 64 |
| `HMAC-SHA512-224` | `HMAC-SHA-512/224`, `HMAC/SHA-512/224`, `HMACSHA-512/224`, `HMAC-SHA512/224`, `HMAC/SHA512/224`, `HMACSHA512/224`, `HMAC/SHA512-224`, `HMACSHA512-224`, `HMAC-SHA512(224)`, `HMAC/SHA512(224)`, `HMACSHA512(224)`, `HMAC-SHA-512(224)`, `HMAC/SHA-512(224)`, `HMACSHA-512(224)` | `1.2.840.113549.2.12` | `macs` and `sha` | `KeyOwned` | 28 |
| `HMAC-SHA512-256` | `HMAC-SHA-512/256`, `HMAC/SHA-512/256`, `HMACSHA-512/256`, `HMAC-SHA512/256`, `HMAC/SHA512/256`, `HMACSHA512/256`, `HMAC/SHA512-256`, `HMACSHA512-256`, `HMAC-SHA512(256)`, `HMAC/SHA512(256)`, `HMACSHA512(256)`, `HMAC-SHA-512(256)`, `HMAC/SHA-512(256)`, `HMACSHA-512(256)` | `1.2.840.113549.2.13` | `macs` and `sha` | `KeyOwned` | 32 |
| `HMAC-SHA3-224` | `HMAC/SHA3-224`, `HMACSHA3-224` | `2.16.840.1.101.3.4.2.13` | `macs` and `keccak` | `KeyOwned` | 28 |
| `HMAC-SHA3-256` | `HMAC/SHA3-256`, `HMACSHA3-256` | `2.16.840.1.101.3.4.2.14` | `macs` and `keccak` | `KeyOwned` | 32 |
| `HMAC-SHA3-384` | `HMAC/SHA3-384`, `HMACSHA3-384` | `2.16.840.1.101.3.4.2.15` | `macs` and `keccak` | `KeyOwned` | 48 |
| `HMAC-SHA3-512` | `HMAC/SHA3-512`, `HMACSHA3-512` | `2.16.840.1.101.3.4.2.16` | `macs` and `keccak` | `KeyOwned` | 64 |
| `HMAC-GOST3411-2012-256` | `HMAC/GOST3411-2012-256`, `HMACGOST3411-2012-256` | `1.2.643.7.1.1.4.1` | `macs` and `gost3411` | `KeyOwned` | 32 |
| `HMAC-GOST3411-2012-512` | `HMAC/GOST3411-2012-512`, `HMACGOST3411-2012-512` | `1.2.643.7.1.1.4.2` | `macs` and `gost3411` | `KeyOwned` | 64 |

### Block cipher MACs

MACs built on a block cipher; the key is the cipher's. Each needs the feature of its MAC and of its
cipher, as `cbc-mac` and `des`.

| Name | Aliases | OIDs | Features | Params | Tag bytes |
|---|---|---|---|---|---|
| `DESMAC` | `DES` |  | `macs` and `des` | `KeyOwned`, `KeyWithIvOwned` | 4 |
| `DESMAC64` | `DES64` |  | `macs` and `des` | `KeyOwned`, `KeyWithIvOwned` | 8 |
| `DESMAC/CFB8` | `DES/CFB8` |  | `macs` and `des` | `KeyOwned`, `KeyWithIvOwned` | 4 |
| `DESEDEMAC` | `DESEDE` | `1.2.840.113549.3.7` | `macs` and `des` | `KeyOwned`, `KeyWithIvOwned` | 4 |
| `DESEDEMAC64` | `DESEDE64` |  | `macs` and `des` | `KeyOwned`, `KeyWithIvOwned` | 8 |
| `DESEDEMAC64WITHISO7816-4PADDING` | `DESEDE64WITHISO7816-4PADDING`, `DESEDEISO9797ALG1MACWITHISO7816-4PADDING`, `DESEDEISO9797ALG1WITHISO7816-4PADDING` |  | `macs` and `des` | `KeyOwned`, `KeyWithIvOwned` | 8 |
| `DESEDEMAC/CFB8` | `DESEDE/CFB8` |  | `macs` and `des` | `KeyOwned`, `KeyWithIvOwned` | 4 |
| `SKIPJACKMAC` | `SKIPJACK` |  | `macs` and `misc-block-cipher` | `KeyOwned`, `KeyWithIvOwned` | 4 |
| `SKIPJACKMAC/CFB8` | `SKIPJACK/CFB8` |  | `macs` and `misc-block-cipher` | `KeyOwned`, `KeyWithIvOwned` | 4 |
| `IDEAMAC` | `IDEA` |  | `macs` and `misc-block-cipher` | `KeyOwned`, `KeyWithIvOwned` | 4 |
| `IDEAMAC/CFB8` | `IDEA/CFB8` |  | `macs` and `misc-block-cipher` | `KeyOwned`, `KeyWithIvOwned` | 4 |
| [`RC2MAC`](Rc2.md) | `RC2` |  | `macs` and `rc-cipher` | `KeyOwned`, `KeyWithIvOwned`, [`Rc2ParamsOwned`](Rc2.md), `ParamsWithIvOwned<Rc2ParamsOwned>` | 4 |
| [`RC2MAC/CFB8`](Rc2.md) | `RC2/CFB8` |  | `macs` and `rc-cipher` | `KeyOwned`, `KeyWithIvOwned`, [`Rc2ParamsOwned`](Rc2.md), `ParamsWithIvOwned<Rc2ParamsOwned>` | 4 |
| [`RC5MAC`](Rc5.md) | `RC5` |  | `macs` and `rc-cipher` | `KeyOwned`, `KeyWithIvOwned`, [`Rc5ParamsOwned`](Rc5.md), `ParamsWithIvOwned<Rc5ParamsOwned>` | 4 |
| [`RC5MAC/CFB8`](Rc5.md) | `RC5/CFB8` |  | `macs` and `rc-cipher` | `KeyOwned`, `KeyWithIvOwned`, [`Rc5ParamsOwned`](Rc5.md), `ParamsWithIvOwned<Rc5ParamsOwned>` | 4 |
| `<CIPHER>CMAC`, for the ciphers below | `<CIPHER>-CMAC` |  | `macs` and the cipher's | `KeyOwned`; RC2, RC5 and GOST 28147 also their own | the block |
| `<CIPHER>GMAC`, for the ciphers below | `<CIPHER>-GMAC` |  | `macs` and the cipher's | `KeyWithIvOwned`; RC5-64 also `ParamsWithIvOwned<Rc5ParamsOwned>` | 16 |

The `MAC` rows are CBC-MAC, and the `MAC/CFB8` rows CFB-MAC with a feedback of 8 bits, both with a
tag of half a block unless the name says 64 bits. The last block is padded with zeros, or with
ISO 7816-4 where the name says so.

CMAC is over `AES`, `ARIA`, `BLOWFISH`, `CAMELLIA`, `CAST5`, `CAST6`, `DES`, `DESEDE`, `GOST28147`,
`IDEA`, `NOEKEON`, `RC2`, `RC5`, `RC5-64`, `RC6`, `SEED`, `SERPENT`, `SKIPJACK`, `SM4`, `TEA`,
`TNEPRES`, `TWOFISH` and `XTEA`, the ciphers of a block of 8 or 16 bytes. GMAC is over those of 16:
`AES`, `ARIA`, `CAMELLIA`, `CAST6`, `NOEKEON`, `RC5-64`, `RC6`, `SEED`, `SERPENT`, `SM4`, `TNEPRES`
and `TWOFISH`.

### Others

| Name | Aliases | OIDs | Feature | Params | Key bytes | Tag bytes |
|---|---|---|---|---|---|---|
| `ISO9797ALG3MAC` | `ISO9797ALG3`, `DESWITHISO9797`, `DESISO9797MAC` |  | `iso9797-mac` | `KeyOwned`, `KeyWithIvOwned` | 16, 24 | 8 |
| `ISO9797ALG3WITHISO7816-4PADDING` | `ISO9797ALG3MACWITHISO7816-4PADDING` |  | `iso9797-mac` | `KeyOwned`, `KeyWithIvOwned` | 16, 24 | 8 |
| [`GOST28147MAC`](Gost28147.md) | `GOST28147` |  | `gost28147-mac` | `KeyOwned`, `KeyWithIvOwned`, [`Gost28147ParamsOwned`](Gost28147.md), `ParamsWithIvOwned<Gost28147ParamsOwned>` | 32 | 4 |
| `VMPCMAC` | `VMPC`, `VMPC-MAC` |  | `macs` | `KeyWithIvOwned` | 16..64 | 20 |
| `SIPHASH-2-4` | `SIPHASH` |  | `macs` | `KeyOwned` | 16 | 8 |
| `SIPHASH-4-8` |  |  | `macs` | `KeyOwned` | 16 | 8 |
| `KMAC128` |  | `2.16.840.1.101.3.4.2.19` | `kmac` | `KeyOwned` | .. | 32 |
| `KMAC256` |  | `2.16.840.1.101.3.4.2.20` | `kmac` | `KeyOwned` | .. | 64 |
| `POLY1305` |  |  | `poly1305` | `KeyOwned` | 32 | 16 |
| `SKEIN-MAC-256-128` | `SKEINMAC-256-128` |  | `skein-mac` | `KeyOwned` | .. | 16 |
| `SKEIN-MAC-256-160` | `SKEINMAC-256-160` |  | `skein-mac` | `KeyOwned` | .. | 20 |
| `SKEIN-MAC-256-224` | `SKEINMAC-256-224` |  | `skein-mac` | `KeyOwned` | .. | 28 |
| `SKEIN-MAC-256-256` | `SKEINMAC-256-256` |  | `skein-mac` | `KeyOwned` | .. | 32 |
| `SKEIN-MAC-512-128` | `SKEINMAC-512-128` |  | `skein-mac` | `KeyOwned` | .. | 16 |
| `SKEIN-MAC-512-160` | `SKEINMAC-512-160` |  | `skein-mac` | `KeyOwned` | .. | 20 |
| `SKEIN-MAC-512-224` | `SKEINMAC-512-224` |  | `skein-mac` | `KeyOwned` | .. | 28 |
| `SKEIN-MAC-512-256` | `SKEINMAC-512-256` |  | `skein-mac` | `KeyOwned` | .. | 32 |
| `SKEIN-MAC-512-384` | `SKEINMAC-512-384` |  | `skein-mac` | `KeyOwned` | .. | 48 |
| `SKEIN-MAC-512-512` | `SKEINMAC-512-512` |  | `skein-mac` | `KeyOwned` | .. | 64 |
| `SKEIN-MAC-1024-384` | `SKEINMAC-1024-384` |  | `skein-mac` | `KeyOwned` | .. | 48 |
| `SKEIN-MAC-1024-512` | `SKEINMAC-1024-512` |  | `skein-mac` | `KeyOwned` | .. | 64 |
| `SKEIN-MAC-1024-1024` | `SKEINMAC-1024-1024` |  | `skein-mac` | `KeyOwned` | .. | 128 |

ISO 9797-1 algorithm 3 is the retail MAC over DES: CBC-MAC under the first key, and the last block
under the two-key or three-key triple DES. KMAC has an empty customization string. Skein-MAC is named
by its state and tag in bits.

## Params

Any other type of params is `InvalidParams`, and so is an IV given to a MAC that takes none, or none
to one that needs it.

A `KeyOwned` is a zero IV where the MAC takes one, as Bouncy Castle takes a `KeyParameter`; an IV
given is a block, for GMAC that of GCM, and for VMPC-MAC 16..64 bytes. The own params of RC2, RC5 and
GOST 28147 go alone or in a `ParamsWithIvOwned`, and a bare key gives them the defaults of their
pages. Every params type wipes the key when dropped.

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
