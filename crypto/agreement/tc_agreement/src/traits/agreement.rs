/// An initialized key agreement, BC's `IRawAgreement`: one party's private key, which turns
/// the other party's public key into their shared secret.
///
/// The secret is written as fixed-length bytes rather than returned as an integer, as BC's
/// `IBasicAgreement` does: an integer drops leading zero bytes, which every caller then has
/// to pad back. Initialization is provided independently by [`AgreementInit`].
pub trait Agreement {
    /// The other party's public key.
    type PublicKey: ?Sized;

    /// The failure type, such as a public key off the curve.
    type Error: core::error::Error;

    /// The length of the shared secret in bytes.
    fn agreement_size(&self) -> usize;

    /// Writes the shared secret with `public_key` into the first
    /// [`agreement_size`](Self::agreement_size) bytes of `output`.
    fn calculate_agreement(
        &self,
        public_key: &Self::PublicKey,
        output: &mut [u8],
    ) -> Result<(), Self::Error>;
}

/// Initializes an agreement from parameters of type `P`, holding the private key.
pub trait AgreementInit<P: ?Sized> {
    /// The failure type, such as a private key out of range.
    type Error: core::error::Error;

    fn init(&mut self, params: &P) -> Result<(), Self::Error>;
}
