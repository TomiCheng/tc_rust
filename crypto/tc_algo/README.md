# tc_algo

One way to call every algorithm: digests, ciphers, MACs, signers, key generators and the rest, each
chosen at run time by a name or an OID, after Bouncy Castle C#'s `Org.BouncyCastle.Security`. A
name such as `"AES/GCM/NOPADDING"` from configuration, or an OID read from a certificate, gives the
algorithm behind a trait object, so a program need not know at compile time which one it runs.

```rust
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    // One entry point for every factory
    let algo = DefaultAlgoBuilder::default().build();
    let hash = algo.digest().calculate_by_name("SHA-256", b"abc")?;
    assert_eq!(hash.len(), 32);
    Ok(())
}
```

Every algorithm is behind a feature, and no feature is on by default: a program builds only the
algorithms it turns on, and a name it did not turn on is an error, not a fallback. The one
exception is `KEY`, a secret key of any length, which is always on.

## Algorithms

- **[Digest](docs/Digest.md)**: a short fingerprint of any data, the same for the same data and
  different for anything changed, from which the data cannot be found again. Mainstream: SHA-256,
  SHA-384 and SHA-512, SHA-3 and BLAKE3.
- **[XOF](docs/Xof.md)**: a digest of any length that is asked for. Mainstream: SHAKE128 and
  SHAKE256.
- **[Key generation](docs/KeyGeneration.md)**: a new secret key for a cipher or a MAC, drawn from a
  random source. Mainstream: AES-128 and AES-256.
- **[Key pair generation](docs/KeyPairGeneration.md)**: a new public key and private key, the public
  one to share and the private one to keep. Mainstream: RSA of 2048 bits or more, EC on P-256 and
  P-384, and ML-KEM.
- **Cipher**: keeps data secret, so that only the holder of the key reads it.
  - **[Block cipher](docs/BlockCipher.md)**: encrypts in blocks, in a mode such as CBC or CTR.
    Mainstream: AES; the others are for formats that name them.
  - **[Stream cipher](docs/StreamCipher.md)**: encrypts byte by byte with a keystream. Mainstream:
    ChaCha20.
  - **[AEAD cipher](docs/AeadCipher.md)**: encrypts and also shows that nothing was changed; the one
    to use for new data. Mainstream: AES-GCM and ChaCha20-Poly1305, and Ascon for small devices.
  - **[Asymmetric cipher](docs/AsymCipher.md)**: encrypts with a public key what only the private
    key decrypts, for short data such as a key. Mainstream: RSA with OAEP. More: [RSA](docs/Rsa.md),
    [ElGamal](docs/ElGamal.md), [Naccache-Stern](docs/NaccacheStern.md), [SM2](docs/Sm2.md)
  - **[IES](docs/IES.md)**: an agreement, a KDF, a MAC and a cipher in one, to encrypt a message of
    any length to a public key. Mainstream: ECIES. More: [ECIES](docs/Ecies.md)
- **[MAC](docs/Mac.md)**: a tag that shows data was not changed and came from someone with the key.
  Mainstream: HMAC-SHA256, AES-CMAC, KMAC and Poly1305.
- **[Signer](docs/Signer.md)**: a signature made with a private key, which anyone with the public
  key can check. Mainstream: ECDSA and RSA-PSS with SHA-256.
- **DRBG**: stretches a little entropy into as many random bytes as wanted. Mainstream: HMAC-DRBG
  over SHA-256. More: [DRBG](docs/Drbg.md)
- **[Key wrap](docs/KeyWrap.md)**: encrypts one key under another, to store or send it. Mainstream:
  AES Key Wrap and AES Key Wrap with Padding.
- **KDF**: derives keys from a shared secret or another key. Mainstream: HKDF over SHA-256. More:
  [HKDF](docs/HKDF-SHA256.md)
- **KEM**: gives two sides one secret, using only the public key of one of them. Mainstream:
  ML-KEM-768. More: [KEM](docs/KEM.md)
- **Agreement**: two sides, each with a key pair, reach one shared secret. Mainstream: DH over the
  groups of RFC 3526 and RFC 7919. More: [Diffie-Hellman](docs/Dh.md)
- **PBE**: a key from a password, for encrypting with it. Mainstream: PKCS#12 with SHA-256 and
  AES-CBC. More: [PBE](docs/Pbe.md)
