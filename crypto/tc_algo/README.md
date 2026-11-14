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
- Ciphers, all from `algo.cipher()`, each a `BufferedCipher` of `tc_buffered_cipher` that code
  written for that trait takes as it is:
  - Block cipher: AES, DES, DESede, Camellia, ARIA, SM4, SEED, Blowfish, Twofish, Serpent, CAST5,
    CAST6, IDEA, RC2, RC5, RC6, GOST 28147, Threefish and more, in ECB, CBC, CFB, OFB, CTR and
    OpenPGP's CFB, with ciphertext stealing in ECB and CBC, and GOFB for a block of 8 bytes; see
    [Block ciphers](docs/BlockCipher.md)
  - Stream cipher: ChaCha20, XChaCha20, Salsa20, XSalsa20, HC-128, HC-256, RC4, VMPC and ISAAC;
    see [Stream ciphers](docs/StreamCipher.md)
  - AEAD cipher: GCM, CCM, EAX and OCB over the block ciphers of a block of 16 bytes, EAX over
    those of 8; see [AEAD ciphers](docs/AeadCipher.md)
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

## Traits

What the factories hand out are the traits of the crates underneath, with `AlgoError` for their
errors and an init that takes any params, so code written for those traits takes them as they are:

- `Cipher`: `BufferedCipher` and `BufferedCipherInit` of `tc_buffered_cipher`
- `Digest`, `Xof`: `TryDigest`, `TryXof` of `tc_digest`
- `Mac`: `Mac` and `MacInit` of `tc_macs`
- `Wrapper`: `KeyWrap` and `KeyWrapInit` of `tc_key_wrap`
- `Signer`: `Signer` and `SignerInit` of `tc_signer`
- `Kdf`: `Kdf` and `KdfInit` of `tc_kdf`
- `Agreement`: `Agreement` and `AgreementInit` of `tc_agreement`
- `KeyPairGenerator`: `KeyPairGenerator` and `KeyPairGeneratorInit` of `tc_asym_cipher`
- `Encapsulator`, `Decapsulator`: `KemEncapsulator`, `KemDecapsulator` and `KemInit` of `tc_kem`,
  one of each for a row, as Bouncy Castle's `KemUtilities` gives them
- `Drbg`: `CryptoRng` of `rand_core`

Each adds only what its crate lacks, such as `finalize` returning a `Vec`. `Xof::init` is its own,
since `tc_digest`'s XOFs take their params when they are made. `Pbe` and `KeyGenerator` are this
crate's own.

## More

- [Digest](docs/Digest.md): names, OIDs, and hashing at once or in parts
- [Key generation](docs/KeyGeneration.md): secret keys and key pairs
