# tc_algo

Factories that create cryptographic algorithms by name or by OID at run time, after
Bouncy Castle C#'s `Org.BouncyCastle.Security`. The name may come from configuration
and the OID from an ASN.1 `AlgorithmIdentifier`. Each kind of operation has a factory
of its own, which gives one type for all of its algorithms, such as `AnyCipher` or
`AnyAgreement`. Each algorithm comes with a Cargo feature of its own.

## Guides

- [Digests](digest.md): message digests such as SHA-256, after `DigestUtilities`.
- [Ciphers](cipher.md): block, stream, AEAD and asymmetric ciphers, after
  `CipherUtilities`.
- [Key generators](generator.md): secret keys and key pairs, after
  `GeneratorUtilities`.
- [Key agreements](agreement.md): DH, ECDH and X25519, after `AgreementUtilities`.
