# Block cipher mode migration

This table records the completed migration of the legacy block-mode crate to
independent crates under `crypto/block_modes`.

| Status | Target crate | Mode |
|:------:|--------------|------|
| ✅ | `tc_ecb` | ECB |
| ✅ | `tc_cbc` | CBC |
| ✅ | `tc_cfb` | CFB, OpenPGP CFB |
| ✅ | `tc_ofb` | OFB, GCTR |
| ✅ | `tc_ctr` | CTR, KCTR |

Legend: ✅ completed, ⬜ TODO.
