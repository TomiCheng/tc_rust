//! Low-level limb-array arithmetic — the assembly-like toolbox beneath the
//! headline components, mirroring Bouncy Castle's `Math.Raw` namespace.
//!
//! Currently holds [`Nat`] (fixed-length unsigned integers), the foundation for
//! custom per-size prime-field curves. Future siblings: `interleave` (bit
//! spreading for GF(2ᵐ) squaring), `mod`-style constant-time inversion.

mod nat;

pub use nat::{Limb, Nat, LIMB_BITS, nat_limbs};
