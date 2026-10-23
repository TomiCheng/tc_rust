/// An initialized key derivation function, BC's `IDerivationFunction`: fills output of any
/// length from the secret given to [`KdfInit`].
///
/// As in BC, whether a second call continues the output or starts it over depends on the
/// function: KDF1 and KDF2 start over, HKDF and the SP 800-108 functions continue.
pub trait Kdf {
    /// The failure type, such as asking for more bytes than the function can derive.
    type Error: core::error::Error;

    /// Fills `output` with derived bytes and returns its length. Fails before `init`.
    fn generate_bytes(&mut self, output: &mut [u8]) -> Result<usize, Self::Error>;
}

/// Initializes a key derivation function from parameters of type `P`, such as a shared secret
/// and optional context.
pub trait KdfInit<P: ?Sized> {
    /// The failure type, such as parameters the function does not take.
    type Error: core::error::Error;

    fn init(&mut self, params: &P) -> Result<(), Self::Error>;
}
