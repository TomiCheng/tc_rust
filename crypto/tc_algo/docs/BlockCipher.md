# Block ciphers

A block cipher keeps a message secret but does not show whether it was changed. For new data, use
an AEAD cipher such as `AES/GCM/NOPADDING`, which does both; see [AEAD ciphers](AeadCipher.md).
The rows here are for formats and protocols that need a mode of their own.

Algorithms: [AES](BlockCipher/AES.md) · [DES](BlockCipher/DES.md) ·
[DESede](BlockCipher/DESede.md) · [Camellia](BlockCipher/Camellia.md) ·
[ARIA](BlockCipher/ARIA.md) · [SM4](BlockCipher/SM4.md) · [SEED](BlockCipher/SEED.md) ·
[Blowfish](BlockCipher/Blowfish.md) · [Twofish](BlockCipher/Twofish.md) ·
[Serpent](BlockCipher/Serpent.md) · [Tnepres](BlockCipher/Tnepres.md) ·
[CAST5](BlockCipher/CAST5.md) · [CAST6](BlockCipher/CAST6.md) · [IDEA](BlockCipher/IDEA.md) ·
[Noekeon](BlockCipher/Noekeon.md) · [Rijndael](BlockCipher/Rijndael.md) ·
[Skipjack](BlockCipher/Skipjack.md) · [TEA](BlockCipher/TEA.md) · [XTEA](BlockCipher/XTEA.md) ·
[RC2](BlockCipher/RC2.md) · [RC5](BlockCipher/RC5.md) · [RC5-64](BlockCipher/RC5-64.md) ·
[RC6](BlockCipher/RC6.md) · [GOST28147](BlockCipher/GOST28147.md) ·
[Threefish-256](BlockCipher/Threefish-256.md) · [Threefish-512](BlockCipher/Threefish-512.md) ·
[Threefish-1024](BlockCipher/Threefish-1024.md) · [DSTU7624-128](BlockCipher/DSTU7624-128.md) ·
[DSTU7624-256](BlockCipher/DSTU7624-256.md) · [DSTU7624-512](BlockCipher/DSTU7624-512.md)

See also: [Weak, legacy and variable-time rows](#weak-legacy-and-variable-time-rows) ·
[PBE names](#pbe-names) · [Modes and paddings](#modes-and-paddings) · [Params](#params) ·
[The IV](#the-iv) · [RC2's effective key size](Rc2.md) · [RC5's rounds](Rc5.md) ·
[GOST 28147's S-box](Gost28147.md) · [Threefish's tweak](Threefish.md)

From a new key to the decrypted message, with AES in CBC mode and PKCS#7 padding. The `aes` feature
of `tc_algo` has the rows, and the IV here comes from `rand` and `rand_core`.

```rust
use rand::rngs::SysRng;
use rand_core::{Rng, UnwrapErr};
use tc_algo::params::{key::KeyOwned, key::KeyParams, cipher::KeyWithIvOwned};
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
matter. Each algorithm has a page of its own, linked above, with a table of its rows. Their Aliases
column gives every other name that finds the row: the other names of the algorithm, as `TDEA` for
`DESEDE`, of the mode and of the padding, and the names that leave the mode or the padding out. The
rules they follow are under [Modes and paddings](#modes-and-paddings).

### PBE names

Bouncy Castle's `CipherUtilities` also takes the names and OIDs of PBE schemes, and gives the
cipher that each scheme encrypts with. These rows take them as aliases and OIDs of that cipher; the
key and the IV still come from the password, through [PBE](Pbe.md) or elsewhere.

- `DES/CBC/PKCS7PADDING`: PKCS#5's `PBEWITHSHA1ANDDES-CBC`, OID `1.2.840.113549.1.5.10`.
- `RC2/CBC/PKCS7PADDING`: PKCS#5's `PBEWITHSHA1ANDRC2-CBC`, `.11`, and PKCS#12's 128- and 40-bit
  RC2, `1.2.840.113549.1.12.1.5` and `.6`. The 5-byte key of the 40-bit one gives 40 effective
  bits, as any bare key gives its length.
- `DESEDE/CBC/PKCS7PADDING`: PKCS#12's three-key and two-key triple DES, `1.2.840.113549.1.12.1.3`
  and `.4`.
- `AES/CBC/PKCS7PADDING`: Bouncy Castle's `PBEWITHSHA...AES-CBC-BC` and
  `PBEWITHMD5...AES-CBC-OPENSSL`, with no OID.
- `ARC4`: PKCS#12's 128- and 40-bit RC4, `1.2.840.113549.1.12.1.1` and `.2`; see
  [Stream ciphers](StreamCipher.md).

Each also takes Bouncy Castle's other spellings, such as `PBEWITHSHA1AND...` for
`PBEWITHSHAAND...`, as the Aliases column lists.

### Weak, legacy and variable-time rows

ECB is weak: it encrypts equal blocks into equal blocks, so the ciphertext shows where the
message repeats. It is here for old data and for building other schemes; for new data, use a mode
with an IV.

DES is weak whatever the mode: its key of 56 bits falls to a search of every key in hours. It is
here for old data only.

DESede is legacy: NIST withdrew it for encryption at the end of 2023. Its block of 8 bytes lets
two blocks of a long message under one key collide, which leaks their XOR (Sweet32), and two-key
DESede has the strength of about 80 bits. It is here for old data only.

Blowfish, CAST5, IDEA, Skipjack, TEA, XTEA, RC2, RC5 and GOST28147 are legacy for the same reason:
a block of 8 bytes, which Sweet32 turns against long messages under one key. Skipjack's key of 80 bits is short
too, and RC2's key schedule is weak. They are here for old data only.

RC5 and RC6 rotate by amounts that depend on the data, which is constant time on processors whose
rotations are, as most are today.

A variable-time cipher looks up tables by bytes of the key and the data, so it can leak them through
cache timing to code that shares the processor. Where that matters, prefer AES, which `tc_aes` runs
in constant time with AES-NI or with its `rustcrypto` feature.

## Modes and paddings

Each algorithm has a row for each mode with each padding it takes:

- ECB and CBC take whole blocks, so they take every padding: `NOPADDING`, `PKCS7PADDING`,
  `ISO10126PADDING`, `ISO7816-4PADDING`, `X923PADDING`, `TBCPADDING`, `ZEROBYTEPADDING` and
  `WITHCTS`.
  With `NOPADDING`, a message that is not a whole number of blocks is `DataLength`.
- CFB, OFB and CTR take a partial last block, so they take `NOPADDING` only. CFB and OFB feed back
  a whole block, or the bits a size after their name gives, as below.
- GOFB, GOST 28147's counter mode (GCTR), takes a partial last block too, so `NOPADDING` only. Its
  counter is two words of 32 bits, so only the algorithms of a block of 8 bytes have its rows, as
  Bouncy Castle's `GOfbBlockCipher` refuses any other.
- GCM, CCM, EAX and OCB, the AEAD modes, are on [AEAD ciphers](AeadCipher.md).
- `WITHCTS`, which Bouncy Castle names as a padding, is ciphertext stealing over ECB or CBC, through
  `tc_cts_modes`: a message of at least one block, and a ciphertext of its length, the last two
  blocks swapped as RFC 3962 does. A message shorter than a block is `DataLength`. Bouncy Castle's
  `CTS` mode is CBC with it, so `AES/CTS/NOPADDING` and `AES/CTS` are `AES/CBC/WITHCTS`.
- OPENPGPCFB, the CFB of OpenPGP (RFC 4880), takes a partial last block too, so `NOPADDING` only.
  It resynchronizes after the first block and two bytes, which OpenPGP fills with a random prefix
  whose last two bytes repeat; OpenPGP passes an IV of zeros. The rows encrypt and decrypt only:
  making and checking the prefix is the caller's, as with Bouncy Castle's `OpenPgpCfbBlockCipher`.

The padding aliases of Bouncy Castle find the same rows: `PKCS7`, `PKCS5PADDING` and `PKCS5` for
`PKCS7PADDING`, `ISO10126D2PADDING` and `ISO10126-2PADDING` for `ISO10126PADDING`, and
`ISO9797-1PADDING` for `ISO7816-4PADDING`, and `X9.23PADDING` for `X923PADDING`; `NONE` is
another name of `ECB`, and `SIC` of `CTR`.

CFB and OFB take a feedback size in bits after their name, as in Bouncy Castle: `AES/CFB8/NOPADDING`
feeds back a byte at a time. The size is a multiple of 8 from 8 to the bits of a block; the tables
write the sizes as `{8..128}`, the multiples of 8 from 8 to 128. A whole block is the row without a
size, so `AES/CFB128/NOPADDING` is `AES/CFB/NOPADDING`, and a size out of the range names no row.
Each row is listed once in `algorithms()`, under its name without a size.

As in Bouncy Castle, a name may also leave the mode or the padding out:

- An empty or missing mode is ECB: `AES//PKCS7PADDING` and `AES` alone are ECB rows.
- An empty or missing padding, or `RAW`, is the mode's default: `PKCS7PADDING` in ECB and CBC,
  and `NOPADDING` in CFB, OFB, CTR, GOFB and OPENPGPCFB. So `AES` is `AES/ECB/PKCS7PADDING`, `AES/CBC` and
  `AES/CBC/RAW` are `AES/CBC/PKCS7PADDING`, and `AES/CTR` is `AES/CTR/NOPADDING`.

- `ISO10126PADDING` fills with random bytes, from the source of `DefaultAlgoBuilder::set_rand`.
- `ZEROBYTEPADDING` drops every zero byte at the end on decryption, so a message that ends in zero
  bytes does not come back whole.

## Params

Each kind of row takes the type of its mode, and any other type is `InvalidParams`:

| Rows | Params |
|---|---|
| ECB | `KeyOwned` |
| CBC, CFB, OFB, CTR, GOFB, OPENPGPCFB | `KeyWithIvOwned` |

Both come from the crates underneath and wipe themselves when dropped.

RC2, RC5, RC5-64, GOST28147 and the Threefish rows also take params of their own, as Bouncy
Castle's `RC2Parameters`, `RC5Parameters`, `ParametersWithSBox` and `TweakableBlockCipherParameters`:
alone in ECB and with the IV in a `ParamsWithIvOwned` in the other modes. See [RC2](Rc2.md),
[RC5](Rc5.md), [GOST 28147](Gost28147.md) and [Threefish](Threefish.md).

## The IV

- Use a new IV for every message under the same key. It is not secret: send it along with the
  ciphertext, since decrypting needs the same one.
- The IV must be one block, 8 bytes for the ciphers of 8-byte blocks and 16 for the others, or
  `init` gives `InvalidParams`. Unlike Bouncy Castle, a short IV is not padded with zeros, and
  there is no default of zeros: `KeyWithIvOwned` always has one to give.
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

- `get_by_name` and `get_by_oid` give a `Cipher`, which is a `BufferedCipher` and a
  `BufferedCipherInit` of `tc_buffered_cipher` with `AlgoError` for its errors, so code written
  for those traits takes it as it is.
- `encrypt_by_name` and `decrypt_by_name` take the whole message at once and give the whole
  result; `by_oid` does the same by OID.
- For a message in parts, `get_by_name` gives a `Cipher`: `init` with the direction and the
  params, then `update` for each part, then `finalize`. `output_len` tells how large a buffer the
  next call needs, for `process_bytes` and `do_final`.
- With no padding, ECB and CBC take whole blocks only: a message of another length is
  `DataLength` from `finalize`. CFB and OFB take any length.
- `reset` starts over with the same key and IV.
