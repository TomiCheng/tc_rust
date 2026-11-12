# tc_algo

Algorithms chosen at run time, by name or by OID, after Bouncy Castle C#'s
`Org.BouncyCastle.Security`. A name such as `"AES/CBC/PKCS7PADDING"` or an OID read from a
certificate gives a digest, a cipher, a signer or a key generator behind a trait object, so a
program can take its algorithms from configuration or from the data it reads.

```rust
use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};

let algo = DefaultAlgoBuilder::default().build();
let hash = algo.digest().calculate_by_name("SHA-256", b"abc")?;
```

Every algorithm is behind a feature, and no feature is on by default: a program builds only the
rows it turns on, and a name it did not turn on is an error, not a fallback.

## Supported algorithms

- Digest: SHA-1, SHA-2, SHA-3, Keccak, SHAKE, MD2, MD4, MD5, BLAKE2b, BLAKE2s, BLAKE3, RIPEMD,
  SM3, GOST R 34.11, DSTU 7564, Tiger, Whirlpool, Ascon, Skein, Haraka, PHOTON-Beetle, ESCH,
  Xoodyak and `NONE`, each name behind a feature of its own, such as `sha256` or `blake2b-512`;
  see [Digest](docs/Digest.md)
- XOF: SHAKE, cSHAKE, TupleHash, ParallelHash, BLAKE2xs, BLAKE3, Ascon-XOF and Ascon-CXOF, each
  behind a feature of its own; see [XOF](docs/Xof.md)
- MAC: `HMAC-SHA256` (`hmac-sha256`)
- Ciphers, all from `algo.cipher()`:
  - Block cipher: AES in ECB, CBC, CFB and OFB (`aes`); see [Block ciphers](docs/BlockCipher.md)
  - Stream cipher: `CHACHA7539` (`chacha`); see [Stream ciphers](docs/StreamCipher.md)
  - AEAD cipher: AES in GCM (`aes`); see [AEAD ciphers](docs/AeadCipher.md)
  - IES: `IES` (`ies`); see [IES](docs/IES.md)
  - Asymmetric cipher: RSA raw, PKCS#1 v1.5 and OAEP (`rsa`); see
    [Asymmetric ciphers](docs/AsymCipher.md)
- Key wrap: `AESWRAP` (`aes-wrap`)
- Key generation: `AES128`, `AES192`, `AES256`, `KEY` (`aes`); key pairs `RSA` (`rsa`), `DH`
  (`dh`), `ML-KEM` (`ml-kem`)
- Signer: `SHA-256withRSA` (`rsa`)
- Agreement: `DH` (`dh`)
- KDF: `HKDF-SHA256`, `HKDF-SHA384`, `HKDF-SHA512` (`hkdf-sha256`, `hkdf-sha384`, `hkdf-sha512`)
- PBE: PKCS#12 with SHA-256 and AES-CBC (`pbe-aes`)
- KEM: `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024` (`ml-kem`)
- DRBG: `HMAC/SHA-256` (`drbg-hmac-sha256`)

## More

- [Digest](docs/Digest.md): names, OIDs, and hashing at once or in parts
- [Key generation](docs/KeyGeneration.md): secret keys and key pairs
