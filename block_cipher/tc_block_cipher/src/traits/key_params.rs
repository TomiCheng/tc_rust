pub trait KeyParams {
    /// Returns the key bytes.
    fn key(&self) -> &[u8];
}