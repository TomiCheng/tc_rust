//! What every asymmetric key tells about itself.

/// What every asymmetric key tells about itself, whatever its algorithm:
/// whether it is private, as Bouncy Castle's `AsymmetricKeyParameter`
/// tells through `IsPrivate`. An encoding over an engine reads it to pick
/// its format, as PKCS#1 v1.5 picks its block type: type 1 for a private
/// key, type 2 for a public one.
pub trait AsymmetricKeyParams {
    /// Whether the key is private. Constant time.
    fn is_private_key(&self) -> bool;
}
