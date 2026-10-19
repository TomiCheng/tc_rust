/// An initialized DSA, BC's `IDsa`: signs the hash of a message as a pair of integers (r, s)
/// in the group order, or verifies such a pair.
///
/// The key given to [`DsaInit`] decides which: a private key signs, a public key verifies.
pub trait Dsa {
    /// The integer type of r, s and the order.
    type Integer;

    /// The failure type, such as signing with a public key.
    type Error: core::error::Error;

    /// The order of the group that r and s belong to. Panics before `init`.
    fn order(&self) -> &Self::Integer;

    /// Signs `message`, usually a hash, and returns (r, s).
    fn generate_signature(
        &mut self,
        message: &[u8],
    ) -> Result<(Self::Integer, Self::Integer), Self::Error>;

    /// Whether (r, s) is a signature of `message`.
    fn verify_signature(
        &self,
        message: &[u8],
        r: &Self::Integer,
        s: &Self::Integer,
    ) -> Result<bool, Self::Error>;
}

/// Initializes a DSA from parameters of type `P`: a private key to sign, a public key to
/// verify.
pub trait DsaInit<P: ?Sized> {
    /// The failure type, such as a key out of range.
    type Error: core::error::Error;

    fn init(&mut self, params: &P) -> Result<(), Self::Error>;
}
