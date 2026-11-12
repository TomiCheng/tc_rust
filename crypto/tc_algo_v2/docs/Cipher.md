# Cipher

`algo.cipher()` gives ciphers by name or by OID: block ciphers in a mode, stream ciphers, AEAD,
RSA and IES, all behind one `Cipher` trait.

## Names

A name is `ALGORITHM/MODE/PADDING`, in capitals, after Bouncy Castle's `CipherUtilities`:

- `AES/ECB/NOPADDING`, `AES/ECB/PKCS7PADDING`
- `AES/CBC/NOPADDING`, `AES/CBC/PKCS7PADDING`
- `AES/CFB/NOPADDING`, `AES/OFB/NOPADDING`
- `AES/GCM/NOPADDING`
- `CHACHA7539`, also `CHACHA20`
- `RSA`, `RSA//PKCS1PADDING`, `RSA//OAEPPADDING`, `RSA//OAEPWITHSHA256ANDMGF1PADDING`
- `IES`

`PKCS5PADDING`, `PKCS5` and `PKCS7` are other names of `PKCS7PADDING`, and `NOPADDING` of the raw
RSA. RSA with PKCS#1 v1.5 also has the OID 1.2.840.113549.1.1.1, and with OAEP 1.2.840.113549.1.1.7.

## Params

`init` takes the direction and a `&dyn Params`; which params a row takes depends on the row:

- `KeyOwned`: a key alone, for ECB
- `KeyWithIvOwned`: a key and an IV, for CBC, CFB, OFB and ChaCha
- `AeadParamsOwned`: a key, a nonce, the tag length and associated data, for GCM
- `RsaKey`: an RSA key, public to encrypt and private to decrypt
- `IesDhParams`: the keys of both sides, for IES

Params of another type are an error from `init`, as is a key of the wrong length.

## Using it

- `encrypt_by_name` and `decrypt_by_name` take the whole message at once and give the whole
  result; `by_oid` does the same by OID.
- For a message in parts, `get_by_name` gives a `Cipher`: `init`, then `update` or
  `process_bytes` for each part, then `finalize` or `do_final`. `output_len` tells how large a
  buffer the next call needs.
- `reset` starts over with the same key and IV.
- `algorithms` lists the rows turned on.

## More

- [RSA](Rsa.md): RSA key pairs, encrypting and signing
- [Block ciphers](BlockCipher.md), [AEAD ciphers](AeadCipher.md), [Stream ciphers](StreamCipher.md),
  [IES](IES.md)
