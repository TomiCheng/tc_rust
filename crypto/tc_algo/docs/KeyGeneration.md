# Key generation

A secret key is one key that both sides share and keep secret, for a block, stream or AEAD cipher,
a MAC or a key wrap. `algo.key_generator()` makes it from a random source. For a public key and a
private key, see [Key pair generation](KeyPairGeneration.md).

The following example requires the `aes` feature. It generates a fresh key for a single AES-GCM message.

```rust
use tc_algo::params::{cipher::AeadParamsOwned, generate::KeyLength, key::KeyOwned, key::KeyParams};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // A 256-bit AES key
    let key = algo.key_generator().generate_by_name("AES256")?;
    let key = key.as_any().downcast_ref::<KeyOwned>().expect("a KeyOwned");
    assert_eq!(key.key().len(), 32);

    // This fresh key is used once. Each further message under the same key needs a unique nonce.
    let params = AeadParamsOwned::new(key.key().to_vec(), vec![0; 12], 16, Vec::new());
    let sealed = algo.cipher().encrypt_by_name("AES/GCM/NOPADDING", &params, b"attack at dawn")?;
    assert_eq!(sealed.len(), b"attack at dawn".len() + 16);

    // A key of any length, such as for HMAC
    let key = algo.key_generator().generate_by_name_with("KEY", &KeyLength::new(64))?;
    let key = key.as_any().downcast_ref::<KeyOwned>().expect("a KeyOwned");
    assert_eq!(key.key().len(), 64);
    Ok(())
}
```

## Algorithms

| Name | Aliases | OIDs | Feature | Default bytes | Bytes | Params | Returns |
|---|---|---|---|---|---|---|---|
| `KEY` |  |  | none, always on | none | 1.. | `KeyLength` | `KeyOwned` |
| `AES128` |  | the eight of AES-128, `2.16.840.1.101.3.4.1.1` to `.8` | `aes` | 16 | 16 |  | `KeyOwned` |
| `AES192` |  | the eight of AES-192, `2.16.840.1.101.3.4.1.21` to `.28` | `aes` | 24 | 24 |  | `KeyOwned` |
| `AES256` |  | the eight of AES-256, `2.16.840.1.101.3.4.1.41` to `.48` | `aes` | 32 | 32 |  | `KeyOwned` |
| `AES` | `AESWRAP` |  | `aes` | 24 | 16, 24, 32 | `KeyLength` | `KeyOwned` |
| `ARIA` |  |  | `aria` | 32 | 16, 24, 32 | `KeyLength` | `KeyOwned` |
| `ARIA128` |  | the ten of ARIA-128 of NSRI | `aria` | 16 | 16 |  | `KeyOwned` |
| `ARIA192` |  | the ten of ARIA-192 of NSRI | `aria` | 24 | 24 |  | `KeyOwned` |
| `ARIA256` |  | the ten of ARIA-256 of NSRI | `aria` | 32 | 32 |  | `KeyOwned` |
| `BLOWFISH` |  | `1.3.6.1.4.1.3029.1.2`, `1.3.6.1.4.1.3029.1.1.2` | `blowfish` | 16 | 4..56 | `KeyLength` | `KeyOwned` |
| `CAMELLIA` | `CAMELLIAWRAP` |  | `camellia` | 32 | 16, 24, 32 | `KeyLength` | `KeyOwned` |
| `CAMELLIA128` |  | `1.2.392.200011.61.1.1.1.2`, `1.2.392.200011.61.1.1.3.2` | `camellia` | 16 | 16 |  | `KeyOwned` |
| `CAMELLIA192` |  | `1.2.392.200011.61.1.1.1.3`, `1.2.392.200011.61.1.1.3.3` | `camellia` | 24 | 24 |  | `KeyOwned` |
| `CAMELLIA256` |  | `1.2.392.200011.61.1.1.1.4`, `1.2.392.200011.61.1.1.3.4` | `camellia` | 32 | 32 |  | `KeyOwned` |
| `CAST5` |  | `1.2.840.113533.7.66.10` | `cast` | 16 | 5..16 | `KeyLength` | `KeyOwned` |
| `CAST6` |  |  | `cast` | 32 | 16, 20, 24, 28, 32 | `KeyLength` | `KeyOwned` |
| `DES` |  | `1.3.14.3.2.7`, `1.3.14.3.2.9`, `1.3.14.3.2.6`, `1.3.14.3.2.8` | `des` | 8 | 8 |  | `KeyOwned` |
| `DESEDE` | `DESEDEWRAP`, `TDEA`, `DESEDE16` | `1.3.14.3.2.17` | `des` | 16 | 16, 24 | `KeyLength` | `KeyOwned` |
| `DESEDE3` | `DESEDE24` | `1.2.840.113549.3.7`, `1.2.840.113549.1.9.16.3.6` | `des` | 24 | 16, 24 | `KeyLength` | `KeyOwned` |
| `IDEA` |  | `1.3.6.1.4.1.188.7.1.1.2` | `misc-block-cipher` | 16 | 16 |  | `KeyOwned` |
| `NOEKEON` |  |  | `misc-block-cipher` | 16 | 16 |  | `KeyOwned` |
| `RC6` |  |  | `rc-cipher` | 32 | 1..255 | `KeyLength` | `KeyOwned` |
| `RIJNDAEL` |  |  | `misc-block-cipher` | 24 | 16, 20, 24, 28, 32 | `KeyLength` | `KeyOwned` |
| `SEED` |  | `1.2.410.200004.7.1.1.1`, `1.2.410.200004.1.4` | `seed` | 16 | 16 |  | `KeyOwned` |
| `SERPENT` |  |  | `serpent` | 24 | 4..32, by 4 | `KeyLength` | `KeyOwned` |
| `SKIPJACK` |  |  | `misc-block-cipher` | 10 | 10 |  | `KeyOwned` |
| `SM4` |  |  | `sm4` | 16 | 16 |  | `KeyOwned` |
| `TEA` |  |  | `misc-block-cipher` | 16 | 16 |  | `KeyOwned` |
| `THREEFISH-256` |  |  | `threefish` | 32 | 32 | [`ThreefishKeyGenParams`](Threefish.md#key-generation) | `ThreefishParamsOwned` |
| `THREEFISH-512` |  |  | `threefish` | 64 | 64 | [`ThreefishKeyGenParams`](Threefish.md#key-generation) | `ThreefishParamsOwned` |
| `THREEFISH-1024` |  |  | `threefish` | 128 | 128 | [`ThreefishKeyGenParams`](Threefish.md#key-generation) | `ThreefishParamsOwned` |
| `TNEPRES` |  |  | `serpent` | 24 | 4..32, by 4 | `KeyLength` | `KeyOwned` |
| `TWOFISH` |  |  | `twofish` | 32 | 16, 24, 32 | `KeyLength` | `KeyOwned` |
| `XTEA` |  |  | `misc-block-cipher` | 16 | 16 |  | `KeyOwned` |
| `CHACHA` |  |  | `chacha` | 16 | 16, 32 | `KeyLength` | `KeyOwned` |
| `CHACHA7539` | `CHACHA20`, `CHACHA20-POLY1305` | `1.2.840.113549.1.9.16.3.18` | `chacha` or `chacha-aead` | 32 | 32 |  | `KeyOwned` |
| `XCHACHA20` | `XCHACHA20-POLY1305` |  | `chacha` or `chacha-aead` | 32 | 32 |  | `KeyOwned` |
| `HC128` |  |  | `hc` | 16 | 16 |  | `KeyOwned` |
| `HC256` |  |  | `hc` | 32 | 16, 32 | `KeyLength` | `KeyOwned` |
| `RC4` | `ARC4` | `1.2.840.113549.3.4` | `rc4-family` | 16 | 1..256 | `KeyLength` | `KeyOwned` |
| `SALSA20` |  |  | `salsa20` | 16 | 16, 32 | `KeyLength` | `KeyOwned` |
| `XSALSA20` |  |  | `salsa20` | 32 | 32 |  | `KeyOwned` |
| `VMPC` |  |  | `rc4-family` | 16 | 16..64 | `KeyLength` | `KeyOwned` |
| `VMPC-KSA3` |  |  | `rc4-family` | 16 | 16..64 | `KeyLength` | `KeyOwned` |
| `ASCON-AEAD128` |  |  | `ascon-aead` | 16 | 16 |  | `KeyOwned` |
| `ASCON-128` |  |  | `ascon-aead` | 16 | 16 |  | `KeyOwned` |
| `ASCON-128A` |  |  | `ascon-aead` | 16 | 16 |  | `KeyOwned` |
| `ASCON-80PQ` |  |  | `ascon-aead` | 20 | 20 |  | `KeyOwned` |
| `GRAIN-128AEAD` |  |  | `grain128-aead` | 16 | 16 |  | `KeyOwned` |
| `SCHWAEMM128-128` |  |  | `sparkle-aead` | 16 | 16 |  | `KeyOwned` |
| `SCHWAEMM256-128` |  |  | `sparkle-aead` | 16 | 16 |  | `KeyOwned` |
| `SCHWAEMM192-192` |  |  | `sparkle-aead` | 24 | 24 |  | `KeyOwned` |
| `SCHWAEMM256-256` |  |  | `sparkle-aead` | 32 | 32 |  | `KeyOwned` |
| `RC2` |  | `1.2.840.113549.3.2`, `1.2.840.113549.1.9.16.3.7` | `rc-cipher` | 16 | 1..128 | [`Rc2KeyGenParams`](Rc2.md#key-generation) | `Rc2ParamsOwned` |
| `RC5` | `RC5-32` |  | `rc-cipher` | 16 | 1..255 | [`Rc5KeyGenParams`](Rc5.md#key-generation) | `Rc5ParamsOwned` |
| `RC5-64` |  |  | `rc-cipher` | 32 | 1..255 | [`Rc5KeyGenParams`](Rc5.md#key-generation) | `Rc5ParamsOwned` |
| `GOST28147` | `GOST`, `GOST-28147` | `1.2.643.2.2.21` | `gost28147` | 32 | 32 | [`Gost28147KeyGenParams`](Gost28147.md#key-generation) | `Gost28147ParamsOwned` |

Bytes are lists (`16, 24, 32`), ranges with both ends included (`16..64`), or with no upper end
(`1..`).

The names, aliases, OIDs and default lengths are those of Bouncy Castle's `GeneratorUtilities`, but
`DESEDE16` and `DESEDE24`, which name the two lengths of DESede, `XSALSA20` and `KEY`, which are
this crate's, as are the AEAD ciphers of their own, Ascon, Grain-128AEAD and Schwaemm, named after
their cipher rows, which Bouncy Castle has no names for there. ChaCha20-Poly1305 and
XChaCha20-Poly1305 take the keys of `CHACHA7539` and `XCHACHA20`, whose aliases they are, and the
AEAD modes of a block cipher, such as `AES/GCM/NOPADDING`, the key of the cipher. ISAAC takes a key
of any length and has no row of its own: `KEY` gives one.

`KEY` needs no feature: it is always on, whatever else a program turns on. Each other row is behind
the feature of its cipher, and the case of a name does not matter. An OID of a
cipher finds the row of its key, so that the OID read from a certificate or a CMS message finds the
generator of its key: the OIDs of AES and ARIA are those of each mode and key wrap of the key
length, of ECB, CBC, CFB, OFB, CCM and GCM and more.

## Params

Key-generation inputs live in `tc_algo::params::generate`. `KeyLength::new(n)` takes bytes.

- Algorithm-specific generators can generate immediately using the default length in the table.
- A blank Params cell means the generator takes no parameters. Calling `init` on it returns
  `InvalidParams`, even with a `KeyLength` equal to the fixed length.
- For rows that accept `KeyLength`, `init` sets one of the lengths in the Bytes column. An
  unsupported length returns `InvalidParams` and preserves the previous length.
- RC2, RC5, RC5-64, GOST 28147 and Threefish have params of their own, so their rows give those
  params, the key with what the cipher takes besides it, and `init` takes a params type of each
  instead of a `KeyLength`; see [RC2](Rc2.md#key-generation), [RC5](Rc5.md#key-generation), [GOST
  28147](Gost28147.md#key-generation) and [Threefish](Threefish.md#key-generation). What they give
  goes straight into the rows of their cipher, in ECB as it is, and with an IV in a
  `ParamsWithIvOwned`.
- `KEY` has no default length: it needs `init` with a `KeyLength`, of any length but 0, and
  `generate_by_name` gives `NotInitialized`; `generate_by_name_with("KEY", &KeyLength::new(32))`
  gives a key at once.

## Using it

- For one key, use `generate_by_name` or `generate_by_oid`. Their `_with` variants call `init`
  with the supplied parameters before generating. For several keys with the same settings, keep
  the generator from `get_by_name` or `get_by_oid` and call `generate()` for each new key.
- Each key is behind `Box<dyn Params>`, of the type of the Returns column, which goes straight into
  what takes it: `as_any().downcast_ref::<KeyOwned>()` returns an `Option<&KeyOwned>`, and `KeyParams::key()` borrows its bytes.
- `DES`, `DESEDE` and `DESEDE3` keep to the rules of their keys, as Bouncy Castle's
  `DesKeyGenerator` and `DesEdeKeyGenerator` do: each byte has odd parity, a weak key is drawn
  again, and so is a DESede key whose parts repeat, which would be DES. `KEY` is only random
  bytes, so it keeps to no rule; use the row of the cipher.
- The keys draw from the source of `DefaultAlgoBuilder::set_rand`, the operating system's unless it
  is given another.
