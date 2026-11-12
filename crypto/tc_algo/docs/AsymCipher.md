# Asymmetric ciphers

An asymmetric cipher encrypts with a public key, and only the private key of the pair decrypts. It
takes one block, of a size set by the key, and a padding of its own rather than a mode. It is for
short data, such as a key for a symmetric cipher, not for messages.

## Algorithms

| Name | Aliases | OIDs | Feature | Params | Note |
|---|---|---|---|---|---|
| `RSA//OAEPWITHSHA256ANDMGF1PADDING` | `OAEPWITHSHA-256ANDMGF1PADDING`, `OAEPWITHSHA256ANDMGF1WITHSHA256PADDING`, `OAEPWITHSHA-256ANDMGF1WITHSHA-256PADDING` |  | `rsa` | `RsaKey` | OAEP over SHA-256 |
| `RSA//OAEPPADDING` | `OAEP`, `OAEPWITHSHA1ANDMGF1PADDING`, `OAEPWITHSHA-1ANDMGF1PADDING` | `1.2.840.113549.1.1.7` | `rsa` | `RsaKey` | OAEP over SHA-1 |
| `RSA//PKCS1PADDING` | `PKCS1` | `1.2.840.113549.1.1.1` | `rsa` | `RsaKey` | PKCS#1 v1.5 |
| `RSA` | `NOPADDING` |  | `rsa` | `RsaKey` | no padding |

The aliases are paddings: each goes after `RSA//`, `RSA/NONE/` or `RSA/ECB/`, so
`RSA/ECB/PKCS1` finds `RSA//PKCS1PADDING`, as does `RSA/NONE/PKCS1PADDING`. The case of a name does
not matter.

## Params

The rows take an `RsaKey`, from `tc_algo::params`: the public key to encrypt, the private key to
decrypt. A key pair from `algo.key_pair_generator()` goes straight in. Params of another type are
`InvalidParams` from `init`.

## Using it

- For new data, use OAEP. PKCS#1 v1.5 can be broken by whoever sees its padding checks fail, and
  `RSA` without padding is for building other schemes only.
- One message is one block: a longer one is `DataLength`. To encrypt more, encrypt a key for a
  symmetric cipher with RSA, and the message with that key.
- `encrypt_by_name` and `decrypt_by_name` take the whole message at once; `get_by_name` gives a
  `Cipher` to `init` with the direction and the key, `update`, then `finalize`.

## More

- [RSA](Rsa.md): key pairs, encrypting and signing, step by step
