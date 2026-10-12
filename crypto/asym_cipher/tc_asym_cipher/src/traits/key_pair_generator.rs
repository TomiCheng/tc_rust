//! Asymmetric key-pair generation contracts.

/// An initialized generator of asymmetric key pairs.
///
/// The generator draws from the random source its parameters carry, as
/// Bouncy Castle's does, and holds it from initialization on.
/// Initialization is provided independently by [`KeyPairGeneratorInit`].
pub trait KeyPairGenerator {
    /// The public key of a generated pair.
    type PublicKey;

    /// The private key of a generated pair.
    type PrivateKey;

    /// The failure type returned while generating a pair.
    type Error: core::error::Error;

    /// Generates a key pair, drawing its randomness from the random source
    /// the generator was initialized with.
    fn generate_key_pair(&mut self) -> Result<(Self::PublicKey, Self::PrivateKey), Self::Error>;
}

/// Initializes a key-pair generator from parameters of type `P`.
///
/// This trait is independent of [`KeyPairGenerator`]. Consumers that need
/// both capabilities use `G: KeyPairGenerator + KeyPairGeneratorInit<P>`,
/// as with the cipher traits.
///
/// Unlike the cipher traits, it takes the parameters by value: they carry
/// the random source, which the generator holds until it generates. The
/// parameters can carry a `&mut` borrow of a source, so the caller keeps
/// it and its state.
pub trait KeyPairGeneratorInit<P> {
    /// The failure type returned by initialization.
    type Error: core::error::Error;

    /// Initializes the generator, such as with the random source, the key
    /// size and, for RSA, the public exponent.
    fn init(&mut self, params: P) -> Result<(), Self::Error>;
}
