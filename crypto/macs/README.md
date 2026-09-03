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
| ✅ Done | `CbcBlockCipherMac` | [`tc_cbc_mac::CbcMac`](tc_cbc_mac) | Allocation-free generic CBC-MAC with optional IV, configurable tag size, zero padding, or caller-selected padding. |
| ✅ Done | `CfbBlockCipherMac` | [`tc_cfb_mac::CfbMac`](tc_cfb_mac) | Allocation-free generic CFB-MAC with optional IV and configurable feedback, tag, and padding. |
| ✅ Done | `CMac` | [`tc_cmac::CMac`](tc_cmac) | Allocation-free generic CMAC, with NIST/BC AES vectors and the BC 64-bit DESede vector. |
| ✅ Done | `Dstu7564Mac` | `tc_dstu_macs::Dstu7564Mac` | Bouncy Castle vectors for 256-, 384-, and 512-bit tags, including the 1023-/1024-byte boundary cases. |
| ✅ Done | `Dstu7624Mac` | [`tc_dstu_macs::Dstu7624Mac`](tc_dstu_macs) | Allocation-free 128-, 256-, and 512-bit-block variants; BC vectors cover 128- and 512-bit blocks. |
| 🟢 Ready | `GMac` | `tc_gmac` | `tc_gcm::GcmBlockCipher<C>` now provides the required GCM authentication core. |
| ✅ Done | `GOST28147Mac` | [`tc_gost28147_mac::Gost28147Mac`](tc_gost28147_mac) | Allocation-free 16-round GOST MAC core with caller-selected S-box and optional IV. |
| ✅ Done | `HMac` | [`tc_hmac::HMac`](tc_hmac) | Generic HMAC over the infallible `Digest` API, with BC/RFC vectors, long-key handling, retained keyed state, and non-`Clone` digest support. |
| ✅ Done | `ISO9797Alg3Mac` | [`tc_iso9797_mac::Iso9797Alg3Mac`](tc_iso9797_mac) | Allocation-free two-/three-key DES Retail MAC, with optional IV, tag truncation, and padding. |
| ✅ Done | `KMac` | [`tc_kmac::KMac`](tc_kmac) | KMAC128/KMAC256 fixed tags and XOF output over cSHAKE; requires `alloc`. |
| ✅ Raw mode | `Poly1305` | [`tc_poly1305`](tc_poly1305) | Raw Poly1305 with a caller-supplied 32-byte one-time key is implemented and tested. The optional 128-bit block-cipher construction is not implemented, but its block-cipher and IV prerequisites are available. |
| ✅ Done | `SipHash` | [`tc_siphash::SipHash`](tc_siphash) | Allocation-free SipHash-c-d; all 64 official SipHash-2-4 vectors pass. |
| 🟡 Partial | `SkeinMac` | `tc_skein_mac` | `tc_skein::SkeinEngine` provides unkeyed UBI, but keyed/parameterized initialization and a shared Skein parameter model are still required. |
| ✅ Done | `VMPCMac` | [`tc_vmpc_mac::VmpcMac`](tc_vmpc_mac) | Allocation-free VMPC-MAC with 16–64-byte key and IV validation. |

Legend:

- ✅ implemented.
- 🟢 all prerequisites are present; implementation can start.
- ⏸ implementation is blocked by a required primitive.

## Prerequisite summary

The shared `Mac` and `MacInit<P>` interfaces are complete. Of the 14 Bouncy
Castle C# MAC types, eleven are fully implemented. Raw Poly1305 is implemented,
while its optional block-cipher construction remains deferred. GMAC can now
wrap `tc_gcm::GcmBlockCipher<C>`. SkeinMac can reuse the unkeyed
Skein engine, but still needs keyed and parameterized Skein initialization.

CMAC is available to the future EAX implementation recorded in the
[`aead_cipher` inventory](../aead_cipher/README.md). No other fully unimplemented
MAC in this inventory is ready without first completing a missing prerequisite.

## Verification

Run the tests for all currently implemented MAC crates from the workspace root:

```bash
cargo test -p tc_macs -p tc_cbc_mac -p tc_cfb_mac -p tc_cmac \
  -p tc_dstu_macs -p tc_gost28147_mac -p tc_hmac -p tc_iso9797_mac \
  -p tc_kmac -p tc_poly1305 -p tc_siphash -p tc_vmpc_mac --locked
```
