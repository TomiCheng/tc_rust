# tc_macs

Message authentication code (MAC) implementations ported from Bouncy Castle's
C# library. Implementations use the `Mac` and `MacInit` traits from
`tc_crypto_core`.

This crate supports `no_std` and does not require `alloc`.

This is a learning project and has not been independently audited. Do not use
it for production cryptography.

## Status

The inventory below covers every public class that directly implements `IMac`
under bc-csharp's `crypto/src/crypto/macs` directory at commit
`20cb1616247e5f79d3dcf662b17ed5beb6922151`.

| Algorithm | bc-csharp class | Rust module | Notes | Status |
| --- | --- | --- | --- | --- |
| CBC-MAC | `CbcBlockCipherMac` | `cbc` | Generic block-cipher MAC with optional padding. | TODO |
| CFB-MAC | `CfbBlockCipherMac` | `cfb` | Generic block-cipher CFB MAC with optional padding. | TODO |
| CMAC | `CMac` | `cmac` | Generic block-cipher CMAC. | TODO |
| DSTU7564 MAC | `Dstu7564Mac` | `dstu7564` | Built from the DSTU7564 digest. | TODO |
| DSTU7624 MAC | `Dstu7624Mac` | `dstu7624` | Uses the DSTU7624 block cipher. | TODO |
| GMAC | `GMac` | `gmac` | Authentication-only use of GCM. | TODO |
| GOST 28147 MAC | `Gost28147Mac` | `gost28147` | GOST 28147-89 MAC. | TODO |
| HMAC | `HMac` | `hmac` | Generic construction over a digest. | TODO |
| ISO/IEC 9797-1 Algorithm 3 MAC | `ISO9797Alg3Mac` | `iso9797_alg3` | DES retail MAC with optional padding. | TODO |
| KMAC | `KMac` | `kmac` | KMAC128/KMAC256 over cSHAKE; also implements bc-csharp `IXof`. | TODO |
| Poly1305 | `Poly1305` | `poly1305` | Raw one-time-key form implemented; optional 128-bit block-cipher form remains TODO. | Raw complete / cipher TODO |
| SipHash | `SipHash` | `siphash` | Configurable SipHash-c-d; defaults to SipHash-2-4. | TODO |
| Skein-MAC | `SkeinMac` | `skein` | Configurable Skein state and output sizes. | TODO |
| VMPC-MAC | `VmpcMac` | `vmpc` | VMPC-based MAC. | TODO |

This is an inventory of implementations, not every name accepted by
bc-csharp's `MacUtilities`. For example, the various HMAC-with-digest names all
instantiate the same `HMac` class, while DES-, Triple-DES-, IDEA-, RC2-, RC5-,
and Skipjack-MAC names select one of the generic block-cipher MAC classes.

The internal `MacCfbBlockCipher` helper is not listed separately because it
does not implement `IMac`; it is an implementation detail of
`CfbBlockCipherMac`.
