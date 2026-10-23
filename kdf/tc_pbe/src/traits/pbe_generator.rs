/// An initialized password-based generator, BC's `PbeParametersGenerator`: derives a cipher key,
/// a cipher key and IV, or a MAC key from the password, salt and iteration count given to
/// [`PbeGeneratorInit`].
///
/// The lengths come from the buffers, in bytes, where BC takes them in bits; turning the bytes
/// into an algorithm's key object, as BC's `algorithm` argument does, is left to the caller.
/// Every call derives from the start, as in BC, so the same parameters give the same bytes.
pub trait PbeGenerator {
    /// The failure type, such as asking for more bytes than the scheme can derive.
    type Error: core::error::Error;

    /// Fills `key`, BC's `GenerateDerivedParameters(algorithm, keySize)`. Fails before `init`.
    fn derive_key(&mut self, key: &mut [u8]) -> Result<(), Self::Error>;

    /// Fills `key` and `iv`, BC's `GenerateDerivedParameters(algorithm, keySize, ivSize)`.
    /// Fails before `init`.
    fn derive_key_and_iv(&mut self, key: &mut [u8], iv: &mut [u8]) -> Result<(), Self::Error>;

    /// Fills `key` for a MAC, BC's `GenerateDerivedMacParameters(keySize)`; only PKCS#12 derives
    /// it differently from a cipher key. Fails before `init`.
    fn derive_mac_key(&mut self, key: &mut [u8]) -> Result<(), Self::Error>;
}

/// Initializes a password-based generator from parameters of type `P`: the password, the salt
/// and the iteration count.
pub trait PbeGeneratorInit<P: ?Sized> {
    /// The failure type, such as an iteration count the scheme does not take.
    type Error: core::error::Error;

    fn init(&mut self, params: &P) -> Result<(), Self::Error>;
}
