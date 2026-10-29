# Message authentication codes

This directory contains message-authentication-code (MAC) implementations.
The inventory below is measured against the current Bouncy Castle C# directory
`crypto/src/crypto/macs`.

All implementations use the shared [`tc_macs`](https://crates.io/crates/tc_macs) contracts:

- `Mac` provides streaming input, finalization, and reset.
- `MacInit<P>` initializes a MAC from caller-selected parameter traits.

Parameter requirements should be expressed with the small traits in
[`tc_params`](../tc_params), such as `KeyParams`, `IvParams`,
`IvOptParams`, `MacSizeParams`, and `SBoxParams`. Callers may therefore
use a convenience parameter type or implement the required traits on their own
type.

> These crates are learning ports and have not received an independent
> security audit. Do not use them as replacements for audited cryptographic
> libraries.

## Implementation status

| Status | Bouncy Castle C# type | Target crate | Prerequisite assessment |
|:------:|-----------------------|--------------|-------------------------|
| ✅ Done | `CbcBlockCipherMac` | [`tc_macs::FixedCbcMac`](https://crates.io/crates/tc_macs) | Published in `tc_macs` over the published block-cipher crates: `FixedCbcMac`, `FixedPaddedCbcMac`, and with `alloc` `CbcMac` and `PaddedCbcMac`, checked against bc-csharp's DES vectors. |
| ✅ Done | `CfbBlockCipherMac` | [`tc_macs::FixedCfbMac`](https://crates.io/crates/tc_macs) | Published in `tc_macs` over the published block-cipher crates: `FixedCfbMac`, `FixedPaddedCfbMac`, and with `alloc` `CfbMac` and `PaddedCfbMac`, checked against bc-csharp's DES vectors. The IV must be one block; Bouncy Castle also zero-extends a shorter one. |
| ✅ Done | `CMac` | [`tc_macs::FixedCmac`](https://crates.io/crates/tc_macs) | Published in `tc_macs` over the published block-cipher crates: `FixedCmac`, and with `alloc` `Cmac`, for 64- and 128-bit blocks, checked against the NIST SP 800-38B AES vectors and bc-csharp's DESede vector. |
| ✅ Done | `Dstu7564Mac` | `tc_dstu_macs::Dstu7564Mac` | Bouncy Castle vectors for 256-, 384-, and 512-bit tags, including the 1023-/1024-byte boundary cases. |
| ✅ Done | `Dstu7624Mac` | [`tc_dstu_macs::Dstu7624Mac`](tc_dstu_macs) | Allocation-free 128-, 256-, and 512-bit-block variants; BC vectors cover 128- and 512-bit blocks. |
| ✅ Done | `GMac` | [`tc_macs::Gmac`](https://crates.io/crates/tc_macs) | Published in `tc_macs` over the published `tc_aead_cipher` GCM, checked against bc-csharp's GMacTest vectors; GCM refuses a repeated key and nonce. |
| ✅ Done | `GOST28147Mac` | [`tc_gost28147_mac::Gost28147Mac`](tc_gost28147_mac) | Allocation-free 16-round GOST MAC core with caller-selected S-box and optional IV. |
| ✅ Done | `HMac` | [`tc_macs::FixedHmac`](https://crates.io/crates/tc_macs) | Published in `tc_macs` with the `hmac` feature: `FixedHmac`, and with `alloc` `Hmac`, over any digest on the published `tc_digest` traits, checked against the RFC 4231 vectors. |
| ✅ Done | `ISO9797Alg3Mac` | [`tc_iso9797_mac::Iso9797Alg3Mac`](tc_iso9797_mac) | Allocation-free two-/three-key DES Retail MAC, with optional IV, tag truncation, and padding. |
| ✅ Done | `KMac` | [`tc_kmac::KMac`](tc_kmac) | KMAC128/KMAC256 fixed tags and XOF output over cSHAKE; requires `alloc`. |
| ✅ Raw mode | `Poly1305` | [`tc_poly1305`](https://crates.io/crates/tc_poly1305) | Published from the tc_macs repository: raw Poly1305 with a caller-supplied 32-byte one-time key. The optional 128-bit block-cipher construction is not implemented. |
| ✅ Done | `SipHash` | [`tc_siphash::SipHash`](tc_siphash) | Allocation-free SipHash-c-d; all 64 official SipHash-2-4 vectors pass. |
| 🟡 Partial | `SkeinMac` | `tc_skein_mac` | `tc_skein::SkeinEngine` provides unkeyed UBI, but keyed/parameterized initialization and a shared Skein parameter model are still required. |
| ✅ Done | `VMPCMac` | [`tc_vmpc_mac::VmpcMac`](tc_vmpc_mac) | Allocation-free VMPC-MAC with 16–64-byte key and IV validation. |

Legend:

- ✅ implemented.
- 🟢 all prerequisites are present; implementation can start.
- ⏸ implementation is blocked by a required primitive.

## Prerequisite summary

The shared `Mac` and `MacInit<P>` interfaces are complete. Of the 14 Bouncy
Castle C# MAC types, twelve are fully implemented. Raw Poly1305 is implemented,
while its optional block-cipher construction remains deferred. SkeinMac can reuse the unkeyed
Skein engine, but still needs keyed and parameterized Skein initialization.

EAX now uses internal shared-cipher CMAC state, as recorded in the
published [`tc_aead_cipher`](https://github.com/TomiCheng/tc_aead_cipher) crate. The remaining SkeinMac
still requires a shared keyed Skein parameter model.

## Verification

Run the tests for all currently implemented MAC crates from the workspace root:

```bash
cargo test \
  -p tc_dstu_macs -p tc_gost28147_mac -p tc_iso9797_mac \
  -p tc_kmac -p tc_siphash -p tc_vmpc_mac --locked
```
