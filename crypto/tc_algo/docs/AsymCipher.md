# Asymmetric ciphers

An asymmetric cipher encrypts with a public key, and only the private key of the pair decrypts. It
takes one block, of a size set by the key, and a padding of its own rather than a mode. It is for
short data, such as a key for a symmetric cipher, not for messages.

## Algorithms

| Name | Aliases | OIDs | Feature | Params | Note |
|---|---|---|---|---|---|
| `RSA` | `NOPADDING`, `RAW` |  | `rsa` | `RsaKey` | no padding |
| `RSA//PKCS1PADDING` | `PKCS1` | `1.2.840.113549.1.1.1` | `rsa` | `RsaKey` | PKCS#1 v1.5 |
| `RSA//OAEPPADDING` | `OAEP`, `OAEPWITHSHA1ANDMGF1PADDING`, `OAEPWITHSHA-1ANDMGF1PADDING` | `1.2.840.113549.1.1.7` | `rsa` | `RsaKey` | OAEP over SHA-1 |
| `RSA//OAEPWITHMD5ANDMGF1PADDING` |  |  | `rsa` | `RsaKey` | OAEP over MD5 |
| `RSA//OAEPWITHSHA224ANDMGF1PADDING` | `OAEPWITHSHA-224ANDMGF1PADDING` |  | `rsa` | `RsaKey` | OAEP over SHA-224 |
| `RSA//OAEPWITHSHA256ANDMGF1PADDING` | `OAEPWITHSHA-256ANDMGF1PADDING`, `OAEPWITHSHA256ANDMGF1WITHSHA256PADDING`, `OAEPWITHSHA-256ANDMGF1WITHSHA-256PADDING` |  | `rsa` | `RsaKey` | OAEP over SHA-256 |
| `RSA//OAEPWITHSHA256ANDMGF1WITHSHA1PADDING` | `OAEPWITHSHA-256ANDMGF1WITHSHA-1PADDING` |  | `rsa` | `RsaKey` | OAEP over SHA-256, MGF1 over SHA-1 |
| `RSA//OAEPWITHSHA384ANDMGF1PADDING` | `OAEPWITHSHA-384ANDMGF1PADDING` |  | `rsa` | `RsaKey` | OAEP over SHA-384 |
| `RSA//OAEPWITHSHA512ANDMGF1PADDING` | `OAEPWITHSHA-512ANDMGF1PADDING` |  | `rsa` | `RsaKey` | OAEP over SHA-512 |
| `RSA//ISO9796-1PADDING` | `ISO9796-1` |  | `rsa` | `RsaKey` | ISO 9796-1, legacy |
| `ELGAMAL` | `NOPADDING`, `RAW` |  | `elgamal` | `ElGamalPublicKey`, `ElGamalPrivateKey` | no padding |
| `ELGAMAL//PKCS1PADDING` | `PKCS1` |  | `elgamal` | `ElGamalPublicKey`, `ElGamalPrivateKey` | PKCS#1 v1.5 |
| `ELGAMAL//OAEPPADDING` | `OAEP`, `OAEPWITHSHA1ANDMGF1PADDING`, `OAEPWITHSHA-1ANDMGF1PADDING` |  | `elgamal` | `ElGamalPublicKey`, `ElGamalPrivateKey` | OAEP over SHA-1 |
| `ELGAMAL//OAEPWITHMD5ANDMGF1PADDING` |  |  | `elgamal` | `ElGamalPublicKey`, `ElGamalPrivateKey` | OAEP over MD5 |
| `ELGAMAL//OAEPWITHSHA224ANDMGF1PADDING` | `OAEPWITHSHA-224ANDMGF1PADDING` |  | `elgamal` | `ElGamalPublicKey`, `ElGamalPrivateKey` | OAEP over SHA-224 |
| `ELGAMAL//OAEPWITHSHA256ANDMGF1PADDING` | `OAEPWITHSHA-256ANDMGF1PADDING`, `OAEPWITHSHA256ANDMGF1WITHSHA256PADDING`, `OAEPWITHSHA-256ANDMGF1WITHSHA-256PADDING` |  | `elgamal` | `ElGamalPublicKey`, `ElGamalPrivateKey` | OAEP over SHA-256 |
| `ELGAMAL//OAEPWITHSHA256ANDMGF1WITHSHA1PADDING` | `OAEPWITHSHA-256ANDMGF1WITHSHA-1PADDING` |  | `elgamal` | `ElGamalPublicKey`, `ElGamalPrivateKey` | OAEP over SHA-256, MGF1 over SHA-1 |
| `ELGAMAL//OAEPWITHSHA384ANDMGF1PADDING` | `OAEPWITHSHA-384ANDMGF1PADDING` |  | `elgamal` | `ElGamalPublicKey`, `ElGamalPrivateKey` | OAEP over SHA-384 |
| `ELGAMAL//OAEPWITHSHA512ANDMGF1PADDING` | `OAEPWITHSHA-512ANDMGF1PADDING` |  | `elgamal` | `ElGamalPublicKey`, `ElGamalPrivateKey` | OAEP over SHA-512 |

The names, aliases and OIDs are those of Bouncy Castle's `CipherUtilities`. The aliases are
paddings: each goes after `RSA//`, `RSA/NONE/` or `RSA/ECB/`, and the same for `ELGAMAL`, so
`RSA/ECB/PKCS1` finds `RSA//PKCS1PADDING`, as does `RSA/NONE/PKCS1PADDING`. The case of a name does
not matter.

OAEP takes one digest for the label and for MGF1, but `OAEPWITHSHA256ANDMGF1WITHSHA1PADDING`, which
hashes the label with SHA-256 and masks with MGF1 over SHA-1, as Java's default for SHA-256 does; it
does not open what SHA-256 throughout sealed. OAEP spends twice the hash and two bytes of the block,
so SHA-512 needs a key of more than 1024 bits.

ISO 9796-1 is RSA's alone, as in Bouncy Castle, whose encoding takes an RSA key; it is here for old
data only. ElGamal has no OID in Bouncy Castle, and its ciphertext is two numbers of the size of
`p`, twice the block of its input.

## Params

The RSA rows take an `RsaKey`, from `tc_algo::params`: the public key to encrypt, the private key
to decrypt. A key pair from `algo.key_pair_generator()` goes straight in. The ElGamal rows take an
`ElGamalPublicKey` to encrypt and an `ElGamalPrivateKey` to decrypt, from `tc_elgamal`. Params of
another type are `InvalidParams` from `init`.

## Using it

- For new data, use OAEP. PKCS#1 v1.5 can be broken by whoever sees its padding checks fail, and
  `RSA` without padding is for building other schemes only.
- One message is one block: a longer one is `DataLength`. To encrypt more, encrypt a key for a
  symmetric cipher with RSA, and the message with that key.
- `encrypt_by_name` and `decrypt_by_name` take the whole message at once; `get_by_name` gives a
  `Cipher` to `init` with the direction and the key, `update`, then `finalize`.

## More

- [RSA](Rsa.md): key pairs, encrypting and signing, step by step
