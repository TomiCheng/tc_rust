# Message authentication codes

This directory contains message-authentication-code (MAC) implementations.
The inventory below is measured against the current Bouncy Castle C# directory
`crypto/src/crypto/macs`.

All implementations use the shared [`tc_macs`](../tc_macs) contracts:

- `Mac` provides streaming input, finalization, and reset.
- `MacInit<P>` initializes a MAC from caller-selected parameter traits.

Parameter requirements should be expressed with the small traits in
[`tc_params`](../tc_params), such as `KeyParams`, `IvParams`,
`OptionalIvParams`, `MacSizeParams`, and `SBoxParams`. Callers may therefore
use a convenience parameter type or implement the required traits on their own
type.

> These crates are learning ports and have not received an independent
> security audit. Do not use them as replacements for audited cryptographic
> libraries.

## Implementation status

| Status | Bouncy Castle C# type | Target crate | Prerequisite assessment |
|:------:|-----------------------|--------------|-------------------------|
| 🟢 Ready | `CbcBlockCipherMac` | `tc_cbc_mac` | `BlockCipher`, `BlockCipherInit<P>`, CBC, and the shared block-padding contract are available. |
| 🟢 Ready | `CfbBlockCipherMac` | `tc_cfb_mac` | `BlockCipher`, `BlockCipherInit<P>`, CFB, and the shared block-padding contract are available. |
| ✅ Done | `CMac` | [`tc_cmac::CMac`](tc_cmac) | Allocation-free generic CMAC, with NIST/BC AES vectors and the BC 64-bit DESede vector. |
| ✅ Done | `Dstu7564Mac` | `tc_dstu_macs::Dstu7564Mac` | Bouncy Castle vectors for 256-, 384-, and 512-bit tags, including the 1023-/1024-byte boundary cases. |
| 🟢 Ready | `Dstu7624Mac` | `tc_dstu_macs` | The 128-, 256-, and 512-bit `tc_dstu7624` engines are available. |
| ⏸ Blocked | `GMac` | `tc_gmac` | GMAC is GCM with all input treated as AAD. A reusable GCM authentication core, including GHASH, is not implemented yet. |
| 🟢 Ready | `GOST28147Mac` | `tc_gost28147_mac` | `tc_gost28147`, its S-box tables, and `SBoxParams` are available. |
| ✅ Done | `HMac` | [`tc_hmac::HMac`](tc_hmac) | Generic HMAC over the infallible `Digest` API, with BC/RFC vectors, long-key handling, retained keyed state, and non-`Clone` digest support. |
| 🟢 Ready | `ISO9797Alg3Mac` | `tc_iso9797_mac` | DES/3DES, CBC, and the shared block-padding contract are available. |
| 🟢 Ready | `KMac` | `tc_kmac` | `tc_keccak::CShakeDigest` and the `Xof` API are available. This implementation will require `alloc`, as the current cSHAKE implementation does. |
| ✅ Raw mode | `Poly1305` | [`tc_poly1305`](tc_poly1305) | Raw Poly1305 with a caller-supplied 32-byte one-time key is implemented and tested. The optional 128-bit block-cipher construction is not implemented, but its block-cipher and IV prerequisites are available. |
| 🟢 Ready | `SipHash` | `tc_siphash` | The algorithm is self-contained and only needs `KeyParams`. |
| 🟡 Partial | `SkeinMac` | `tc_skein_mac` | `tc_skein::SkeinEngine` provides unkeyed UBI, but keyed/parameterized initialization and a shared Skein parameter model are still required. |
| 🟢 Ready | `VMPCMac` | `tc_vmpc_mac` | The algorithm is self-contained, and the key/IV parameter traits are available. `tc_vmpc` has equivalent KSA logic, but that private helper would need to be extracted before the two crates could share it. |

Legend:

- ✅ implemented.
- 🟢 all prerequisites are present; implementation can start.
- ⏸ implementation is blocked by a required primitive.

## Prerequisite summary

The shared `Mac` and `MacInit<P>` interfaces are complete. Of the 14 Bouncy
Castle C# MAC types:

- twelve have all required primitives available, including the already
  implemented CMAC, DSTU 7564 MAC, HMAC, and raw Poly1305;
- GMAC is blocked by the missing GCM/GHASH authentication core;
- SkeinMac can reuse the unkeyed Skein engine, but still needs keyed and
  parameterized initialization.

CMAC is now available to the future EAX implementation recorded in the
[`aead_cipher` inventory](../aead_cipher/README.md). The remaining ready,
self-contained algorithms can be ported independently. GMAC and SkeinMac
should remain deferred until their missing authentication core and parameter
model are available.

## Verification

Run the tests for all currently implemented MAC crates from the workspace root:

```bash
cargo test -p tc_macs -p tc_cmac -p tc_dstu_macs -p tc_hmac -p tc_poly1305 --locked
```
