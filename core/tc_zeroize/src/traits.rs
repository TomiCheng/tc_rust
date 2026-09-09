//! Contracts for explicit erasure and opt-in erasure on drop.

/// Explicitly erases a value's contents in its current storage.
///
/// Implementations must use volatile writes followed by a compiler fence, or
/// delegate to implementations that do. Composite types should clear every
/// secret-bearing field. This does not impose a drop policy or erase copies,
/// inaccessible old allocations, or padding bytes.
///
/// ```
/// use tc_zeroize::Zeroize;
///
/// struct Scratch([u32; 2]);
/// impl Zeroize for Scratch {
///     fn zeroize(&mut self) {
///         self.0.zeroize();
///     }
/// }
/// let mut scratch = Scratch([5, 9]);
/// scratch.zeroize();
/// assert_eq!(scratch.0, [0; 2]);
/// ```
pub trait Zeroize {
    /// Overwrites the contents using volatile writes and a compiler fence to
    /// prevent removal of the wipe.
    fn zeroize(&mut self);
}

/// Marks a type that erases its contents when dropped.
///
/// Implementors must provide their own `Drop` implementation that calls
/// [`Zeroize::zeroize`]. This marker generates no behavior and does not enforce
/// that requirement. It expresses a policy for types that know they hold
/// secrets, rather than for general-purpose storage types.
///
/// ```
/// use tc_zeroize::{Zeroize, ZeroizeOnDrop};
///
/// struct Secret([u8; 32]);
/// impl Zeroize for Secret {
///     fn zeroize(&mut self) {
///         self.0.zeroize();
///     }
/// }
/// impl Drop for Secret {
///     fn drop(&mut self) {
///         self.zeroize();
///     }
/// }
/// impl ZeroizeOnDrop for Secret {}
/// let _secret = Secret([7; 32]);
/// ```
pub trait ZeroizeOnDrop {}
