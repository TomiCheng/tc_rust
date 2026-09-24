pub trait IvParams {
    /// Returns the initialization-vector bytes.
    fn iv(&self) -> &[u8];
}
