//! X25519 — RFC 7748 Diffie–Hellman on Curve25519 (Montgomery form).
//!
//! Ported from Bouncy Castle's `Org.BouncyCastle.Math.EC.Rfc7748.X25519`. The core is
//! a constant-time Montgomery ladder over the [`Fe`] base field: given a clamped
//! scalar `k` and a `u`-coordinate, it computes `k · u` — the shared secret.
//!
//! [`Fe`]: super::x25519_field::Fe

/// Byte length of a `u`-coordinate / output point (RFC 7748 `PointSize`).
pub const POINT_SIZE: usize = 32;
/// Byte length of a scalar / private key (RFC 7748 `ScalarSize`).
pub const SCALAR_SIZE: usize = 32;

/// Curve25519 Montgomery coefficient `A = 486662` (`By² = x³ + Ax² + x`). bc `C_A`.
const C_A: i32 = 486662;
/// The ladder constant `a24 = (A + 2) / 4 = 121666`. bc `C_A24`; the `× a24` step uses
/// [`Fe::mul_i32`](super::x25519_field::Fe::mul_i32).
const C_A24: i32 = (C_A + 2) / 4;

// 骨架階段確保常數被使用（ladder 接上後 C_A24 就會餵給 mul_i32）。
const _: () = assert!(C_A24 == 121666);

// TODO(x25519-ladder): port the constant-time Montgomery ladder `ScalarMult(k, u)`
// (clamp + decode scalar, cswap-driven ladder over Fe, final invert + encode), then
// verify against the RFC 7748 test vectors.
//
// TODO(x25519-base): `ScalarMultBase` (public key from private key) uses the Edwards
// base-point mult (bc routes it through Ed25519), so it depends on the rfc8032 line —
// deferred until Ed25519 exists. (The generic ladder with u = 9 also works.)
