# Block cipher migration

This table tracks the migration from the legacy `crates/tc_block_cipher` crate
to independent crates under `crypto/block_cipher`.

| Status | Target crate | Algorithms / engines |
|:------:|--------------|----------------------|
| ✅ | `tc_aes` | AES, AES light, AES-NI |
| ✅ | `tc_aria` | ARIA-128, ARIA-192, ARIA-256 |
| ✅ | `tc_blowfish` | Blowfish |
| ✅ | `tc_camellia` | Camellia, Camellia light |
| ✅ | `tc_cast` | CAST5, CAST6 |
| ✅ | `tc_des` | DES, two-key and three-key Triple DES |
| ✅ | `tc_dstu7624` | DSTU 7624 (Kalyna) |
| ⬜ | `tc_gost28147` | GOST 28147-89 |
| ✅ | `tc_idea` | IDEA |
| ✅ | `tc_noekeon` | Noekeon |
| ⬜ | `tc_rc2` | RC2 |
| ⬜ | `tc_rc5` | RC5-32, RC5-64 |
| ⬜ | `tc_rc6` | RC6 |
| ⬜ | `tc_rijndael` | Rijndael |
| ✅ | `tc_seed` | SEED |
| ✅ | `tc_serpent` | Serpent, Tnepres |
| ✅ | `tc_skipjack` | SKIPJACK |
| ✅ | `tc_sm4` | SM4 |
| ✅ | `tc_tea` | TEA, XTEA |
| ⬜ | `tc_threefish` | Threefish-256, Threefish-512, Threefish-1024 |
| ✅ | `tc_twofish` | Twofish |

Legend: ✅ completed, ⬜ TODO.
