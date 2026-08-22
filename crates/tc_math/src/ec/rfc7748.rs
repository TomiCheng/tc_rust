//! RFC 7748 Montgomery-curve Diffie–Hellman: **X25519** (and later X448).
//!
//! Ported from Bouncy Castle's `Org.BouncyCastle.Math.EC.Rfc7748`. This is the third
//! EC route (alongside prime-field Fp and binary-field F2m): a **different curve
//! model** (Montgomery `By² = x³ + Ax² + x`) with its own constant-time, fixed-size
//! field arithmetic — it does **not** build on the generic `BigInteger`-backed
//! Fp/F2m layers.
//!
//! Layering: [`x25519_field`] (the `GF(2²⁵⁵ − 19)` base field) is the foundation; the
//! X25519 Montgomery ladder sits on top (added later). X448 mirrors it.

pub mod x25519_field;
