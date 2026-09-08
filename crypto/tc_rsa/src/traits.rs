//! Key and raw-operation contracts for RSA.

use rand_core::CryptoRng;
use tc_cipher::CipherDirection;

/// A key usable by an RSA operation: a modulus plus one exponent.
///
/// # Byte contract
///
/// Every byte slice returned by this trait is an unsigned big-endian
/// representation of a non-negative integer:
///
/// - Big-endian: the most significant byte comes first.
/// - Leading zero bytes are permitted and carry no meaning, so `[0x00, 0x05]`
///   and `[0x05]` denote the same value.
/// - An empty slice denotes zero, exactly as an all-zero slice does.
///
/// Nothing here promises the value is a *valid* RSA parameter; validation
/// belongs to the operation that consumes the key.
pub trait RsaKeyParams {
    /// Returns whether this key's exponent is secret.
    fn is_private_key(&self) -> bool;

    /// Returns the modulus `n`.
    fn modulus(&self) -> &[u8];

    /// Returns the exponent: `e` for a public key, `d` for a private one.
    fn exponent(&self) -> &[u8];
}

/// A private key carrying Chinese Remainder Theorem factors.
///
/// Extends [`RsaKeyParams`], so `modulus()` is still `n` and `exponent()` is
/// still `d`; this trait only adds the values the CRT fast path needs. Its
/// slices follow the same [byte contract](RsaKeyParams#byte-contract):
/// unsigned big-endian, leading zeros permitted, empty meaning zero.
pub trait RsaPrivateCrtKeyParams: RsaKeyParams {
    /// Returns the public exponent `e`, used by blinding and the Lenstra
    /// fault check.
    fn public_exponent(&self) -> &[u8];

    /// Returns the prime factor `p`.
    fn p(&self) -> &[u8];

    /// Returns the prime factor `q`.
    fn q(&self) -> &[u8];

    /// Returns `d mod (p - 1)`.
    fn dp(&self) -> &[u8];

    /// Returns `d mod (q - 1)`.
    fn dq(&self) -> &[u8];

    /// Returns `q^-1 mod p`.
    fn q_inv(&self) -> &[u8];
}

/// Raw RSA operations with separate byte conversion and integer processing.
///
/// This trait carries no key type, so an initialized engine can be used — and
/// stored behind `dyn Rsa<RsaBigInt = _, Error = _>` — without naming the
/// parameters it was built from. Initialization is provided independently by
/// [`RsaInit`].
pub trait Rsa {
    type RsaBigInt;
    type Error: core::error::Error;

    /// Returns the maximum input length in bytes for the current direction.
    fn input_block_size(&self) -> usize;

    /// Returns the maximum output length in bytes for the current direction.
    fn output_block_size(&self) -> usize;

    /// Validates and converts a big-endian input block to an unsigned integer.
    fn convert_input(&self, input: &[u8]) -> Result<Self::RsaBigInt, Self::Error>;

    /// Applies the raw RSA operation to a converted input integer.
    fn process_block(&mut self, input: &Self::RsaBigInt) -> Result<Self::RsaBigInt, Self::Error>;

    /// Writes the result in big-endian form and returns the number of bytes written.
    ///
    /// Encryption output is padded to the modulus length; decryption output uses
    /// the shortest unsigned representation. Returns an error if the output
    /// buffer is too small.
    fn convert_output(
        &self,
        result: &Self::RsaBigInt,
        output: &mut [u8],
    ) -> Result<usize, Self::Error>;
}

/// Initializes an RSA engine from key parameters of type `K`.
///
/// Independent from [`Rsa`], so the operation methods stay free of the key
/// type. Consumers that need both write
/// `E: Rsa + RsaInit<K>`.
pub trait RsaInit<K: RsaKeyParams + ?Sized> {
    /// The failure type returned by initialization.
    type Error: core::error::Error;

    /// Initializes the operation direction and key.
    fn init(&mut self, direction: CipherDirection, parameters: &K) -> Result<(), Self::Error>;
}

/// A CRT-capable RSA engine, whose private operation is blinded per call.
pub trait RsaCrt: Rsa {
    /// Applies the CRT private operation with freshly sampled RSA blinding.
    fn process_block_blinded<R: CryptoRng + ?Sized>(
        &mut self,
        input: &Self::RsaBigInt,
        rng: &mut R,
    ) -> Result<Self::RsaBigInt, Self::Error>;
}

/// Initializes a CRT engine from private key parameters of type `K`.
pub trait RsaCrtInit<K: RsaPrivateCrtKeyParams + ?Sized> {
    /// The failure type returned by initialization.
    type Error: core::error::Error;

    /// Initializes the operation direction and CRT key.
    fn init(&mut self, direction: CipherDirection, parameters: &K) -> Result<(), Self::Error>;
}
