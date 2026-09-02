# AEAD ciphers

This directory contains authenticated-encryption with associated-data (AEAD)
implementations. The inventory below is measured against the AEAD engines and
block-cipher modes in the current Bouncy Castle C# source tree at
`crypto/src/crypto/engines` and `crypto/src/crypto/modes`.

All implementations use the shared `tc_cipher::AeadCipher` and
`tc_cipher::AeadCipherInit<P>` contracts. Parameter requirements are expressed
through traits from `tc_params`; callers may use each crate's convenience type
or implement the required traits on their own parameter type.

## Implemented

| Status | Algorithm | Crate and public API | Verification |
|--------|-----------|----------------------|--------------|
| ✅ Done | Ascon-AEAD128 | `tc_ascon_aead::aead128::Engine` | Finalized NIST SP 800-232 vectors |
| ✅ Done | Grain-128AEAD | `tc_grain128_aead::Engine` | Official and Bouncy Castle C# vectors |
| ✅ Done | Grain-128AEAD, fixed AAD capacity | `tc_grain128_aead::FixedEngine<MAX_AAD_LEN>` | Official vector; tested without `alloc` |
| ✅ Done | SCHWAEMM128-128 | `tc_sparkle_aead::Engine` with `Variant::Schwaemm128_128` | Official SCHWAEMM vectors |
| ✅ Done | SCHWAEMM256-128 | `tc_sparkle_aead::Engine` with `Variant::Schwaemm256_128` | Official SCHWAEMM vectors |
| ✅ Done | SCHWAEMM192-192 | `tc_sparkle_aead::Engine` with `Variant::Schwaemm192_192` | Official SCHWAEMM vectors |
| ✅ Done | SCHWAEMM256-256 | `tc_sparkle_aead::Engine` with `Variant::Schwaemm256_256` | Official SCHWAEMM vectors |

The SCHWAEMM implementation currently uses its portable SPARKLE permutation.
The Bouncy Castle C# SSE2 fast path remains an optimization TODO; it does not
affect algorithm availability or test-vector compatibility.

## Not yet implemented

| Status | Algorithm or family | Bouncy Castle C# type | Current prerequisite or decision |
|--------|---------------------|-----------------------|----------------------------------|
| ⬜ TODO | ChaCha20-Poly1305 | `ChaCha20Poly1305` | Compose `tc_chacha::ChaCha7539Engine` with `tc_poly1305::Engine` |
| ⬜ TODO | XChaCha20-Poly1305 | `XChaCha20Poly1305` | Compose `tc_chacha::XChaCha20Engine` with `tc_poly1305::Engine` |
| ⬜ TODO | CCM | `CcmBlockCipher` | Add a generic AEAD block-cipher composition |
| ⬜ TODO | EAX | `EaxBlockCipher` | Add CMAC/CTR composition over `BlockCipher` traits |
| ⬜ TODO | GCM | `GcmBlockCipher` | Add GHASH and a generic block-cipher composition |
| ⬜ TODO | GCM-SIV | `GcmSivBlockCipher` | Add POLYVAL and the misuse-resistant AEAD construction |
| ⬜ TODO | OCB | `OcbBlockCipher` | Add the generic OCB block-cipher construction |
| ⬜ TODO | KCCM | `KCcmBlockCipher` | Add the DSTU 7624-oriented CCM construction |
| ⬜ Deferred | Legacy Ascon v1.2: Ascon-128, Ascon-128a, Ascon-80pq | Deprecated `AsconEngine` | Keep separate from finalized Ascon-AEAD128 to prevent accidental interchange |

The list intentionally excludes ordinary confidentiality-only block modes and
interfaces such as `IAeadCipher` itself.

## Crates

| Crate | Contents |
|-------|----------|
| `tc_ascon_aead` | Finalized Ascon-AEAD128 |
| `tc_grain128_aead` | Growable and allocation-free fixed-capacity Grain-128AEAD engines |
| `tc_sparkle_aead` | All four SCHWAEMM parameter sets |

## Verification

Run all currently implemented AEAD tests from the workspace root:

```bash
cargo test -p tc_ascon_aead -p tc_grain128_aead -p tc_sparkle_aead --locked
```

Verify the allocation-free Grain implementation separately:

```bash
cargo test -p tc_grain128_aead --no-default-features --test fixed_engine --locked
```
