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
| 🟡 Partial | `CbcBlockCipherMac` | `tc_cbc_mac` | `BlockCipher`, `BlockCipherInit<P>`, and CBC are available. The default zero-padded form can be implemented now; support for caller-selected padding still needs a shared block-padding contract. |
| 🟡 Partial | `CfbBlockCipherMac` | `tc_cfb_mac` | `BlockCipher`, `BlockCipherInit<P>`, and CFB are available. The default zero-padded form can be implemented now; support for caller-selected padding still needs a shared block-padding contract. |
| ⏸ Blocked | `CMac` | `tc_cmac` | The generic block-cipher contracts and 64-/128-bit block ciphers are available, but Bouncy Castle uses `ISO7816d4Padding` for CMAC's incomplete final block. Add the shared padding contract and ISO/IEC 7816-4 padding first instead of duplicating that operation inside this crate. |
| ✅ Done | `Dstu7564Mac` | `tc_dstu_macs::Dstu7564Mac` | Bouncy Castle vectors for 256-, 384-, and 512-bit tags, including the 1023-/1024-byte boundary cases. |
| 🟢 Ready | `Dstu7624Mac` | `tc_dstu_macs` | The 128-, 256-, and 512-bit `tc_dstu7624` engines are available. |
| ⏸ Blocked | `GMac` | `tc_gmac` | GMAC is GCM with all input treated as AAD. A reusable GCM authentication core, including GHASH, is not implemented yet. |
| 🟢 Ready | `GOST28147Mac` | `tc_gost28147_mac` | `tc_gost28147`, its S-box tables, and `SBoxParams` are available. |
| 🟢 Ready | `HMac` | `tc_hmac` | `TryDigest` exposes `digest_size`, `byte_length`, streaming input, finalization, and reset, so the required digest API is complete. |
| 🟡 Partial | `ISO9797Alg3Mac` | `tc_iso9797_mac` | DES/3DES and CBC are available. The default zero-padded form can be implemented now; alternate padding still needs a shared block-padding contract. |
| 🟢 Ready | `KMac` | `tc_kmac` | `tc_keccak::CShakeDigest` and the `Xof` API are available. This implementation will require `alloc`, as the current cSHAKE implementation does. |
| ✅ Raw mode | `Poly1305` | [`tc_poly1305`](tc_poly1305) | Raw Poly1305 with a caller-supplied 32-byte one-time key is implemented and tested. The optional 128-bit block-cipher construction is not implemented, but its block-cipher and IV prerequisites are available. |
| 🟢 Ready | `SipHash` | `tc_siphash` | The algorithm is self-contained and only needs `KeyParams`. |
| ⏸ Blocked | `SkeinMac` | `tc_skein_mac` | `tc_threefish` exists, but the Skein UBI engine and Skein parameter model are not implemented. |
| 🟢 Ready | `VMPCMac` | `tc_vmpc_mac` | The algorithm is self-contained, and the key/IV parameter traits are available. `tc_vmpc` has equivalent KSA logic, but that private helper would need to be extracted before the two crates could share it. |

Legend:

- ✅ implemented.
- 🟢 all prerequisites are present; implementation can start.
- 🟡 the default construction can start, but full Bouncy Castle API parity has
  an optional prerequisite still missing.
- ⏸ implementation is blocked by a required primitive.

## Prerequisite summary

The shared `Mac` and `MacInit<P>` interfaces are complete. Of the 14 Bouncy
Castle C# MAC types:

- eight have all required primitives available, including the already
  implemented DSTU 7564 MAC and raw Poly1305;
- three block-cipher MACs can be implemented in their default zero-padded form,
  but need a shared block-padding abstraction for full constructor parity;
- CMAC is blocked by the missing padding contract and ISO/IEC 7816-4 padding;
- GMAC is blocked by the missing GCM/GHASH authentication core;
- SkeinMac is blocked by the missing Skein engine.

The padding contract and ISO/IEC 7816-4 padding should be implemented before
`tc_cmac`. Completing CMAC then removes the remaining MAC prerequisite recorded
for EAX in the [`aead_cipher` inventory](../aead_cipher/README.md). The ready,
self-contained algorithms can otherwise be ported independently. GMAC and
SkeinMac should remain deferred until their required primitives exist.

## Verification

Run the tests for all currently implemented MAC crates from the workspace root:

```bash
cargo test -p tc_macs -p tc_dstu_macs -p tc_poly1305 --locked
```
