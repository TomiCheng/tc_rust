/// An initialized signer, BC's `ISigner`: takes a message in pieces and signs it, or
/// verifies a signature over it.
///
/// The key given to [`SignerInit`] decides which: a private key signs, a public key verifies.
pub trait Signer {
    /// The failure type, such as signing with a public key.
    type Error: core::error::Error;

    /// The most bytes a signature takes, BC's `GetMaxSignatureSize`. Panics before `init`.
    fn max_signature_size(&self) -> usize;

    /// Adds `input` to the message. Fails before `init`.
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error>;

    /// Signs the message into the front of `output` and returns the signature's length,
    /// which can vary, as a DER one does. The next message starts empty.
    fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, Self::Error>;

    /// Whether `signature` is a signature of the message. The next message starts empty.
    fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, Self::Error>;

    /// Discards the message, keeping the key.
    fn reset(&mut self);
}

/// Initializes a signer from parameters of type `P`: a private key to sign, a public key to
/// verify.
pub trait SignerInit<P: ?Sized> {
    /// The failure type, such as a key out of range.
    type Error: core::error::Error;

    fn init(&mut self, params: &P) -> Result<(), Self::Error>;
}
