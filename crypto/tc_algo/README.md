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
algorithms it turns on, and a name it did not turn on is an error, not a fallback.

## Algorithms

- **[Digest](docs/Digest.md)**: a short fingerprint of any data, the same for the same data and
  different for anything changed, from which the data cannot be found again. Mainstream: SHA-256,
  SHA-384 and SHA-512, SHA-3 and BLAKE3.
- **[XOF](docs/Xof.md)**: a digest of any length that is asked for. Mainstream: SHAKE128 and
  SHAKE256.
- **[Key generation](docs/KeyGeneration.md)**: a new secret key for a cipher or a MAC, drawn from a
  random source. Mainstream: AES-128 and AES-256.
- **Key pair generation**: a new public key and private key, the public one to share and the private
  one to keep. Mainstream: RSA of 2048 bits or more, EC on P-256 and P-384, and ML-KEM for a
  quantum-safe exchange; also DH, ElGamal, Naccache-Stern and SM2, and EC on 94 named curves. More:
  [Key pair generation](docs/KeyPairGeneration.md), [EC](docs/Ec.md)
- **Cipher**: keeps data secret, so that only the holder of the key reads it.
  - Block cipher: encrypts in blocks, in a mode such as CBC or CTR. Mainstream: AES; the others are
    for formats that name them. More: [Block ciphers](docs/BlockCipher.md)
  - Stream cipher: encrypts byte by byte with a keystream. Mainstream: ChaCha20. More: [Stream
    ciphers](docs/StreamCipher.md)
  - AEAD cipher: encrypts and also shows that nothing was changed; the one to use for new data.
    Mainstream: AES-GCM and ChaCha20-Poly1305, and Ascon for small devices. More: [AEAD
    ciphers](docs/AeadCipher.md)
  - Asymmetric cipher: encrypts with a public key what only the private key decrypts, for short data
    such as a key. Mainstream: RSA with OAEP. More: [Asymmetric ciphers](docs/AsymCipher.md),
    [RSA](docs/Rsa.md), [ElGamal](docs/ElGamal.md), [Naccache-Stern](docs/NaccacheStern.md),
    [SM2](docs/Sm2.md)
  - IES: an agreement, a KDF, a MAC and a cipher in one, to encrypt a message of any length to a
    public key. Mainstream: ECIES. More: [IES](docs/IES.md), [ECIES](docs/Ecies.md)
- **MAC**: a tag that shows data was not changed and came from someone with the key. Mainstream:
  HMAC-SHA256. More: [MAC](docs/Mac.md)
- **Signer**: a signature made with a private key, which anyone with the public key can check.
  Mainstream: RSA with SHA-256. More: [RSA](docs/Rsa.md#signing)
- **DRBG**: stretches a little entropy into as many random bytes as wanted. Mainstream: HMAC-DRBG
  over SHA-256. More: [DRBG](docs/Drbg.md)
- **Key wrap**: encrypts one key under another, to store or send it. Mainstream: AES Key Wrap. More:
  [Key wrap](docs/KeyWrap.md)
- **KDF**: derives keys from a shared secret or another key. Mainstream: HKDF over SHA-256. More:
  [HKDF](docs/HKDF-SHA256.md)
- **KEM**: gives two sides one secret, using only the public key of one of them. Mainstream:
  ML-KEM-768. More: [KEM](docs/KEM.md)
- **Agreement**: two sides, each with a key pair, reach one shared secret. Mainstream: DH over the
  groups of RFC 3526 and RFC 7919. More: [Diffie-Hellman](docs/Dh.md)
- **PBE**: a key from a password, for encrypting with it. Mainstream: PKCS#12 with SHA-256 and
  AES-CBC. More: [PBE](docs/Pbe.md)
