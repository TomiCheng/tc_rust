# Block ciphers

A block cipher keeps a message secret but does not show whether it was changed. For new data, use
an AEAD cipher such as `AES/GCM/NOPADDING`, which does both; see [AEAD ciphers](AeadCipher.md).
The rows here are for formats and protocols that need a mode of their own.

From a new key to the decrypted message, with AES in CBC mode and PKCS#7 padding. The `aes` feature
of `tc_algo` has the rows, and the IV here comes from `rand` and `rand_core`.

```rust
use rand::rngs::SysRng;
use rand_core::{Rng, UnwrapErr};
use tc_algo::params::{KeyOwned, KeyParams, KeyWithIvOwned};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let name = "AES/CBC/PKCS7PADDING";
    let message = b"attack at dawn";

    // Generate a key
    let key = algo.key_generator().generate_by_name("AES256")?;
    let key = key
        .as_any()
        .downcast_ref::<KeyOwned>()
        .expect("AES256 generates a KeyOwned");

    // Set a new IV
    let mut iv = vec![0; 16];
    UnwrapErr(SysRng).fill_bytes(&mut iv);
    let params = KeyWithIvOwned::new(key.key().to_vec(), iv);

    // Encrypt
    let ciphertext = algo.cipher().encrypt_by_name(name, &params, message)?;

    // Decrypt
    let plaintext = algo.cipher().decrypt_by_name(name, &params, &ciphertext)?;

    assert_eq!(plaintext, message);
    Ok(())
}
```

## Algorithms

A name is `ALGORITHM/MODE/PADDING`, after Bouncy Castle's `CipherUtilities`, and its case does not
matter. The aliases of modes and paddings are under [Modes and paddings](#modes-and-paddings).

### AES

The `aes` feature has the rows.

| Name | OIDs | Params | Note |
|---|---|---|---|
| `AES/ECB/NOPADDING` |  | `KeyOwned` | weak |
| `AES/ECB/PKCS7PADDING` | `2.16.840.1.101.3.4.1.1`, `.21`, `.41` | `KeyOwned` | weak |
| `AES/ECB/ISO10126PADDING` |  | `KeyOwned` | weak |
| `AES/ECB/ISO7816-4PADDING` |  | `KeyOwned` | weak |
| `AES/ECB/X923PADDING` |  | `KeyOwned` | weak |
| `AES/ECB/TBCPADDING` |  | `KeyOwned` | weak |
| `AES/ECB/ZEROBYTEPADDING` |  | `KeyOwned` | weak |
| `AES/CBC/NOPADDING` |  | `KeyWithIvOwned` |  |
| `AES/CBC/PKCS7PADDING` | `2.16.840.1.101.3.4.1.2`, `.22`, `.42` | `KeyWithIvOwned` |  |
| `AES/CBC/ISO10126PADDING` |  | `KeyWithIvOwned` |  |
| `AES/CBC/ISO7816-4PADDING` |  | `KeyWithIvOwned` |  |
| `AES/CBC/X923PADDING` |  | `KeyWithIvOwned` |  |
| `AES/CBC/TBCPADDING` |  | `KeyWithIvOwned` |  |
| `AES/CBC/ZEROBYTEPADDING` |  | `KeyWithIvOwned` |  |
| `AES/CFB/NOPADDING` | `2.16.840.1.101.3.4.1.4`, `.24`, `.44` | `KeyWithIvOwned` |  |
| `AES/OFB/NOPADDING` | `2.16.840.1.101.3.4.1.3`, `.23`, `.43` | `KeyWithIvOwned` |  |
| `AES/CTR/NOPADDING` |  | `KeyWithIvOwned` |  |

The OIDs are NIST's for AES-128, AES-192 and AES-256 in each mode; as in Bouncy Castle, those of ECB
and CBC mean PKCS#7 padding. All three find the same row, so the length of the key comes from the
params.

`AES/GCM/NOPADDING` is an AEAD cipher, on [AEAD ciphers](AeadCipher.md).

### DES

The `des` feature has the rows.

| Name | OIDs | Params | Note |
|---|---|---|---|
| `DES/ECB/NOPADDING` |  | `KeyOwned` | weak |
| `DES/ECB/PKCS7PADDING` | `1.3.14.3.2.6` | `KeyOwned` | weak |
| `DES/ECB/ISO10126PADDING` |  | `KeyOwned` | weak |
| `DES/ECB/ISO7816-4PADDING` |  | `KeyOwned` | weak |
| `DES/ECB/X923PADDING` |  | `KeyOwned` | weak |
| `DES/ECB/TBCPADDING` |  | `KeyOwned` | weak |
| `DES/ECB/ZEROBYTEPADDING` |  | `KeyOwned` | weak |
| `DES/CBC/NOPADDING` |  | `KeyWithIvOwned` | weak |
| `DES/CBC/PKCS7PADDING` | `1.3.14.3.2.7` | `KeyWithIvOwned` | weak |
| `DES/CBC/ISO10126PADDING` |  | `KeyWithIvOwned` | weak |
| `DES/CBC/ISO7816-4PADDING` |  | `KeyWithIvOwned` | weak |
| `DES/CBC/X923PADDING` |  | `KeyWithIvOwned` | weak |
| `DES/CBC/TBCPADDING` |  | `KeyWithIvOwned` | weak |
| `DES/CBC/ZEROBYTEPADDING` |  | `KeyWithIvOwned` | weak |
| `DES/CFB/NOPADDING` | `1.3.14.3.2.9` | `KeyWithIvOwned` | weak |
| `DES/OFB/NOPADDING` | `1.3.14.3.2.8` | `KeyWithIvOwned` | weak |
| `DES/CTR/NOPADDING` |  | `KeyWithIvOwned` | weak |

The OIDs are OIW's, and as in Bouncy Castle those of ECB and CBC mean PKCS#7 padding.

### DESede

The `desede` feature has the rows. `TDEA` is another name of `DESEDE`, as in
`TDEA/CBC/PKCS7PADDING`. The key is 24 bytes for three keys, or 16 for two, the third key being the
first.

| Name | OIDs | Params | Note |
|---|---|---|---|
| `DESEDE/ECB/NOPADDING` |  | `KeyOwned` | weak |
| `DESEDE/ECB/PKCS7PADDING` | `1.3.14.3.2.17` | `KeyOwned` | weak |
| `DESEDE/ECB/ISO10126PADDING` |  | `KeyOwned` | weak |
| `DESEDE/ECB/ISO7816-4PADDING` |  | `KeyOwned` | weak |
| `DESEDE/ECB/X923PADDING` |  | `KeyOwned` | weak |
| `DESEDE/ECB/TBCPADDING` |  | `KeyOwned` | weak |
| `DESEDE/ECB/ZEROBYTEPADDING` |  | `KeyOwned` | weak |
| `DESEDE/CBC/NOPADDING` |  | `KeyWithIvOwned` | legacy |
| `DESEDE/CBC/PKCS7PADDING` | `1.2.840.113549.3.7` | `KeyWithIvOwned` | legacy |
| `DESEDE/CBC/ISO10126PADDING` |  | `KeyWithIvOwned` | legacy |
| `DESEDE/CBC/ISO7816-4PADDING` |  | `KeyWithIvOwned` | legacy |
| `DESEDE/CBC/X923PADDING` |  | `KeyWithIvOwned` | legacy |
| `DESEDE/CBC/TBCPADDING` |  | `KeyWithIvOwned` | legacy |
| `DESEDE/CBC/ZEROBYTEPADDING` |  | `KeyWithIvOwned` | legacy |
| `DESEDE/CFB/NOPADDING` |  | `KeyWithIvOwned` | legacy |
| `DESEDE/OFB/NOPADDING` |  | `KeyWithIvOwned` | legacy |
| `DESEDE/CTR/NOPADDING` |  | `KeyWithIvOwned` | legacy |

The OIDs are OIW's DESede, which means ECB with PKCS#7 padding, and RSA's DES-EDE3-CBC, which means
CBC with PKCS#7 padding.

### Camellia

The `camellia` feature has the rows. A block of 16 bytes and a key of 16, 24 or 32, as AES; a
Japanese and ISO standard.

| Name | OIDs | Params | Note |
|---|---|---|---|
| `CAMELLIA/ECB/NOPADDING` |  | `KeyOwned` | weak, variable time |
| `CAMELLIA/ECB/PKCS7PADDING` |  | `KeyOwned` | weak, variable time |
| `CAMELLIA/ECB/ISO10126PADDING` |  | `KeyOwned` | weak, variable time |
| `CAMELLIA/ECB/ISO7816-4PADDING` |  | `KeyOwned` | weak, variable time |
| `CAMELLIA/ECB/X923PADDING` |  | `KeyOwned` | weak, variable time |
| `CAMELLIA/ECB/TBCPADDING` |  | `KeyOwned` | weak, variable time |
| `CAMELLIA/ECB/ZEROBYTEPADDING` |  | `KeyOwned` | weak, variable time |
| `CAMELLIA/CBC/NOPADDING` |  | `KeyWithIvOwned` | variable time |
| `CAMELLIA/CBC/PKCS7PADDING` | `1.2.392.200011.61.1.1.1.2`, `.3`, `.4` | `KeyWithIvOwned` | variable time |
| `CAMELLIA/CBC/ISO10126PADDING` |  | `KeyWithIvOwned` | variable time |
| `CAMELLIA/CBC/ISO7816-4PADDING` |  | `KeyWithIvOwned` | variable time |
| `CAMELLIA/CBC/X923PADDING` |  | `KeyWithIvOwned` | variable time |
| `CAMELLIA/CBC/TBCPADDING` |  | `KeyWithIvOwned` | variable time |
| `CAMELLIA/CBC/ZEROBYTEPADDING` |  | `KeyWithIvOwned` | variable time |
| `CAMELLIA/CFB/NOPADDING` |  | `KeyWithIvOwned` | variable time |
| `CAMELLIA/OFB/NOPADDING` |  | `KeyWithIvOwned` | variable time |
| `CAMELLIA/CTR/NOPADDING` |  | `KeyWithIvOwned` | variable time |

The OIDs are NTT's for 128-, 192- and 256-bit keys, and mean CBC with PKCS#7 padding.

### ARIA

The `aria` feature has the rows. A block of 16 bytes and a key of 16, 24 or 32, as AES; the Korean
standard.

| Name | OIDs | Params | Note |
|---|---|---|---|
| `ARIA/ECB/NOPADDING` |  | `KeyOwned` | weak, variable time |
| `ARIA/ECB/PKCS7PADDING` | `1.2.410.200046.1.1.1`, `.6`, `.11` | `KeyOwned` | weak, variable time |
| `ARIA/ECB/ISO10126PADDING` |  | `KeyOwned` | weak, variable time |
| `ARIA/ECB/ISO7816-4PADDING` |  | `KeyOwned` | weak, variable time |
| `ARIA/ECB/X923PADDING` |  | `KeyOwned` | weak, variable time |
| `ARIA/ECB/TBCPADDING` |  | `KeyOwned` | weak, variable time |
| `ARIA/ECB/ZEROBYTEPADDING` |  | `KeyOwned` | weak, variable time |
| `ARIA/CBC/NOPADDING` |  | `KeyWithIvOwned` | variable time |
| `ARIA/CBC/PKCS7PADDING` | `1.2.410.200046.1.1.2`, `.7`, `.12` | `KeyWithIvOwned` | variable time |
| `ARIA/CBC/ISO10126PADDING` |  | `KeyWithIvOwned` | variable time |
| `ARIA/CBC/ISO7816-4PADDING` |  | `KeyWithIvOwned` | variable time |
| `ARIA/CBC/X923PADDING` |  | `KeyWithIvOwned` | variable time |
| `ARIA/CBC/TBCPADDING` |  | `KeyWithIvOwned` | variable time |
| `ARIA/CBC/ZEROBYTEPADDING` |  | `KeyWithIvOwned` | variable time |
| `ARIA/CFB/NOPADDING` | `1.2.410.200046.1.1.3`, `.8`, `.13` | `KeyWithIvOwned` | variable time |
| `ARIA/OFB/NOPADDING` | `1.2.410.200046.1.1.4`, `.9`, `.14` | `KeyWithIvOwned` | variable time |
| `ARIA/CTR/NOPADDING` | `1.2.410.200046.1.1.5`, `.10`, `.15` | `KeyWithIvOwned` | variable time |

The OIDs are NSRI's for 128-, 192- and 256-bit keys in each mode. Bouncy Castle also has ARIA in GCM
and CCM, and `ARIA//PKCS7` and the like for ECB with PKCS#7 padding; they are not rows yet.

### SM4

The `sm4` feature has the rows. A block of 16 bytes and a key of 16; the Chinese standard.

| Name | OIDs | Params | Note |
|---|---|---|---|
| `SM4/ECB/NOPADDING` |  | `KeyOwned` | weak, variable time |
| `SM4/ECB/PKCS7PADDING` |  | `KeyOwned` | weak, variable time |
| `SM4/ECB/ISO10126PADDING` |  | `KeyOwned` | weak, variable time |
| `SM4/ECB/ISO7816-4PADDING` |  | `KeyOwned` | weak, variable time |
| `SM4/ECB/X923PADDING` |  | `KeyOwned` | weak, variable time |
| `SM4/ECB/TBCPADDING` |  | `KeyOwned` | weak, variable time |
| `SM4/ECB/ZEROBYTEPADDING` |  | `KeyOwned` | weak, variable time |
| `SM4/CBC/NOPADDING` |  | `KeyWithIvOwned` | variable time |
| `SM4/CBC/PKCS7PADDING` |  | `KeyWithIvOwned` | variable time |
| `SM4/CBC/ISO10126PADDING` |  | `KeyWithIvOwned` | variable time |
| `SM4/CBC/ISO7816-4PADDING` |  | `KeyWithIvOwned` | variable time |
| `SM4/CBC/X923PADDING` |  | `KeyWithIvOwned` | variable time |
| `SM4/CBC/TBCPADDING` |  | `KeyWithIvOwned` | variable time |
| `SM4/CBC/ZEROBYTEPADDING` |  | `KeyWithIvOwned` | variable time |
| `SM4/CFB/NOPADDING` |  | `KeyWithIvOwned` | variable time |
| `SM4/OFB/NOPADDING` |  | `KeyWithIvOwned` | variable time |
| `SM4/CTR/NOPADDING` |  | `KeyWithIvOwned` | variable time |

Bouncy Castle gives SM4 no OID here.

### SEED

The `seed` feature has the rows. A block of 16 bytes and a key of 16; a Korean standard.

| Name | OIDs | Params | Note |
|---|---|---|---|
| `SEED/ECB/NOPADDING` |  | `KeyOwned` | weak, variable time |
| `SEED/ECB/PKCS7PADDING` |  | `KeyOwned` | weak, variable time |
| `SEED/ECB/ISO10126PADDING` |  | `KeyOwned` | weak, variable time |
| `SEED/ECB/ISO7816-4PADDING` |  | `KeyOwned` | weak, variable time |
| `SEED/ECB/X923PADDING` |  | `KeyOwned` | weak, variable time |
| `SEED/ECB/TBCPADDING` |  | `KeyOwned` | weak, variable time |
| `SEED/ECB/ZEROBYTEPADDING` |  | `KeyOwned` | weak, variable time |
| `SEED/CBC/NOPADDING` |  | `KeyWithIvOwned` | variable time |
| `SEED/CBC/PKCS7PADDING` | `1.2.410.200004.1.4` | `KeyWithIvOwned` | variable time |
| `SEED/CBC/ISO10126PADDING` |  | `KeyWithIvOwned` | variable time |
| `SEED/CBC/ISO7816-4PADDING` |  | `KeyWithIvOwned` | variable time |
| `SEED/CBC/X923PADDING` |  | `KeyWithIvOwned` | variable time |
| `SEED/CBC/TBCPADDING` |  | `KeyWithIvOwned` | variable time |
| `SEED/CBC/ZEROBYTEPADDING` |  | `KeyWithIvOwned` | variable time |
| `SEED/CFB/NOPADDING` |  | `KeyWithIvOwned` | variable time |
| `SEED/OFB/NOPADDING` |  | `KeyWithIvOwned` | variable time |
| `SEED/CTR/NOPADDING` |  | `KeyWithIvOwned` | variable time |

The OID is KISA's, and means CBC with PKCS#7 padding.

### Weak, legacy and variable-time rows

ECB is weak: it encrypts equal blocks into equal blocks, so the ciphertext shows where the
message repeats. It is here for old data and for building other schemes; for new data, use a mode
with an IV.

DES is weak whatever the mode: its key of 56 bits falls to a search of every key in hours. It is
here for old data only.

DESede is legacy: NIST withdrew it for encryption at the end of 2023. Its block of 8 bytes lets
two blocks of a long message under one key collide, which leaks their XOR (Sweet32), and two-key
DESede has the strength of about 80 bits. It is here for old data only.

A variable-time cipher looks up tables by bytes of the key and the data, so it can leak them through
cache timing to code that shares the processor. Where that matters, prefer AES, which `tc_aes` runs
in constant time with AES-NI or with its `rustcrypto` feature.

## Modes and paddings

Each algorithm has a row for each mode with each padding it takes:

- ECB and CBC take whole blocks, so they take every padding: `NOPADDING`, `PKCS7PADDING`,
  `ISO10126PADDING`, `ISO7816-4PADDING`, `X923PADDING`, `TBCPADDING` and `ZEROBYTEPADDING`.
  With `NOPADDING`, a message that is not a whole number of blocks is `DataLength`.
- CFB, OFB and CTR take a partial last block, so they take `NOPADDING` only. CFB and OFB feed back
  a whole block.

The padding aliases of Bouncy Castle find the same rows: `PKCS7`, `PKCS5PADDING` and `PKCS5` for
`PKCS7PADDING`, `ISO10126D2PADDING` and `ISO10126-2PADDING` for `ISO10126PADDING`, and
`ISO9797-1PADDING` for `ISO7816-4PADDING`; `SIC` is another name of `CTR`.

- `ISO10126PADDING` fills with random bytes, from the source of `DefaultAlgoBuilder::set_rand`.
- `ZEROBYTEPADDING` drops every zero byte at the end on decryption, so a message that ends in zero
  bytes does not come back whole.

## Params

Each kind of row takes the type of its mode, and any other type is `InvalidParams`:

| Rows | Params |
|---|---|
| ECB | `KeyOwned` |
| CBC, CFB, OFB, CTR | `KeyWithIvOwned` |

Both come from the crates underneath and wipe themselves when dropped.

## The IV

- Use a new IV for every message under the same key. It is not secret: send it along with the
  ciphertext, since decrypting needs the same one.
- The IV must be one block, 8 bytes for DES and DESede and 16 for the others, or `init` gives
  `InvalidParams`. Unlike Bouncy Castle, a short IV is not padded with zeros, and there is no
  default of zeros: `KeyWithIvOwned` always has one to give.
- CTR is the exception: its IV may be shorter than a block, and the rest of the block is the
  counter, which starts at zero.
- `finalize` goes back to the same IV, as in Bouncy Castle. So give each message a new `init` with a
  new IV: a second message without one repeats the IV, which in OFB repeats the whole keystream and
  in CFB its first block. Nothing checks this, and `init` takes an IV it has seen before.
- ECB has no IV. A generated key goes straight into it:

  ```rust
  let ciphertext = algo
      .cipher()
      .encrypt_by_name("AES/ECB/PKCS7PADDING", key.as_ref(), message)?;
  ```

## Keys

- `AES128`, `AES192` and `AES256` generate keys of 16, 24 and 32 bytes. The NIST OID of a mode finds
  the generator of its key length too, as `id-aes256-CBC` does for `AES256`.
- A generated key is a `KeyOwned`, so adding an IV takes a downcast and a new `KeyWithIvOwned`, as
  above. Both hold a copy of the key.

## Authentication

CBC does not detect a changed ciphertext, and the padding check can reveal the plaintext to whoever
can see it fail. Authenticate the ciphertext before decrypting it, or use an AEAD mode.

## Using it

- `encrypt_by_name` and `decrypt_by_name` take the whole message at once and give the whole
  result; `by_oid` does the same by OID.
- For a message in parts, `get_by_name` gives a `Cipher`: `init` with the direction and the
  params, then `update` for each part, then `finalize`. `output_len` tells how large a buffer the
  next call needs, for `process_bytes` and `do_final`.
- With no padding, ECB and CBC take whole blocks only: a message of another length is
  `DataLength` from `finalize`. CFB and OFB take any length.
- `reset` starts over with the same key and IV.
