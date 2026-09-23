/// Provides borrowed access to cipher key bytes.
///
/// Implement this trait for a custom parameter container, or use
/// [`crate::KeyRef`], [`crate::KeyFixed`] or the optional `KeyOwned` type.
/// Key-length validation belongs to the receiving engine.
/// This trait imposes no ownership or wiping policy.
pub trait KeyParams {
    /// Borrows the key bytes for as long as the parameter container is borrowed.
    ///
    /// The returned slice is secret material; avoid logging or retaining copies
    /// unnecessarily. Timing is implementation-defined; the supplied containers
    /// return their slice without inspecting its contents.
    fn key(&self) -> &[u8];
}
