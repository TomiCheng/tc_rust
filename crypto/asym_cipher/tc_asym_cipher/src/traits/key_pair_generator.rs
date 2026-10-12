//! Asymmetric key-pair generation contracts.

/// An initialized generator of asymmetric key pairs.
///
/// The generator holds its own random source, given when it is built, as
/// Bouncy Castle's holds the one its parameters carry; it can hold a
/// `&mut` borrow of one, so the caller keeps the source and its state.
/// Initialization is provided independently by [`KeyPairGeneratorInit`].
pub trait KeyPairGenerator {
    /// The public key of a generated pair.
    type PublicKey;

    /// The private key of a generated pair.
    type PrivateKey;

    /// The failure type returned while generating a pair.
    type Error: core::error::Error;

    /// Generates a key pair, drawing its randomness from the generator's
    /// random source.
    fn generate_key_pair(&mut self) -> Result<(Self::PublicKey, Self::PrivateKey), Self::Error>;
}

/// Initializes a key-pair generator from parameters of type `P`.
///
/// This trait is independent of [`KeyPairGenerator`]. Consumers that need
/// both capabilities use `G: KeyPairGenerator + KeyPairGeneratorInit<P>`,
/// as with the cipher traits.
pub trait KeyPairGeneratorInit<P: ?Sized> {
    /// The failure type returned by initialization.
    type Error: core::error::Error;

    /// Initializes the generator, such as with the key size and, for RSA,
    /// the public exponent.
    fn init(&mut self, params: &P) -> Result<(), Self::Error>;
}
