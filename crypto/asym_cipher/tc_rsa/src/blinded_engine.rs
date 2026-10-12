//! An RSA engine with blinding, as Bouncy Castle's `RsaBlindedEngine`.

use rand_core::CryptoRng;
use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};

use crate::{RsaBlinding, RsaError};

/// An RSA engine `E` with blinding, drawing from the random source `R` it
/// holds, as Bouncy Castle's `RsaBlindedEngine` wraps its core engine: each
/// block goes through [`RsaBlinding::process_block_blinded`], with a fresh
/// `r`, which keeps what the private power works on random and unrelated to
/// the input, against attacks that time it or watch it otherwise. `R` can
/// be a `&mut` borrow, so the caller keeps the source and its state. There
/// is no `Debug`, which would show the state of the source.
///
/// ```
/// # #[cfg(feature = "alloc")] {
/// use tc_asym_cipher::{
///     AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection, KeyPairGenerator,
///     KeyPairGeneratorInit,
/// };
/// use tc_bigint::{FixedBigUint, Word};
/// use tc_rsa_v2::{
///     FixedRsaCoreEngine, FixedRsaCrtCoreEngine, RsaBlindedEngine, RsaKeyGenerationParamsOwned,
///     RsaKeyPairGenerator,
/// };
///
/// type U2048 = FixedBigUint<{ 2048 / Word::BITS as usize }>;
/// type U1024 = FixedBigUint<{ 1024 / Word::BITS as usize }>;
///
/// // 1. Generate a key pair, its primes at half the width of the modulus.
/// let mut generator = RsaKeyPairGenerator::<U2048, U1024>::new();
/// generator.init(RsaKeyGenerationParamsOwned::new(rand::rng()))?;
/// let (public, private) = generator.generate_key_pair()?;
///
/// // 2. Encrypt a block with the public key. Raw RSA is shown here; a real
/// //    message goes through a padding, such as OAEP, first.
/// let message = b"a block of at most 255 bytes";
/// let mut encrypt = FixedRsaCoreEngine::new();
/// encrypt.init(CipherDirection::Encrypt, &public)?;
/// let mut ciphertext = [0; 256];
/// encrypt.process_block(message, &mut ciphertext)?;
///
/// // 3. Decrypt it through the CRT, blinded with the system's random
/// //    source: the result is the same, but the power never sees the
/// //    ciphertext itself.
/// let mut decrypt = RsaBlindedEngine::from_parts(FixedRsaCrtCoreEngine::new(), rand::rng());
/// decrypt.init(CipherDirection::Decrypt, &private)?;
/// let mut plaintext = [0; 256];
/// decrypt.process_block(&ciphertext, &mut plaintext)?;
/// let recovered = &plaintext[256 - message.len()..];
/// # }
/// # Ok::<(), tc_rsa_v2::RsaError>(())
/// ```
pub struct RsaBlindedEngine<E, R> {
    engine: E,
    rng: R,
}

impl<E: Default, R> RsaBlindedEngine<E, R> {
    /// A new engine `E`, to be initialized, drawing from `rng`. Constant
    /// time.
    pub fn new(rng: R) -> Self {
        Self::from_parts(E::default(), rng)
    }
}

impl<E, R> RsaBlindedEngine<E, R> {
    /// `engine`, initialized or not, drawing from `rng`. Constant time.
    pub const fn from_parts(engine: E, rng: R) -> Self {
        Self { engine, rng }
    }

    /// The engine and the random source back. Constant time.
    pub fn into_parts(self) -> (E, R) {
        (self.engine, self.rng)
    }
}

/// Writes the name of the engine, as Bouncy Castle's `RsaBlindedEngine`
/// names itself after its core. Timing is that of the engine's `Display`.
impl<E: core::fmt::Display, R> core::fmt::Display for RsaBlindedEngine<E, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.engine.fmt(f)
    }
}

/// Initializes the engine with `params`, as it is initialized alone.
/// Timing is that of the engine's `init`.
impl<E, R, P> AsymmetricBlockCipherInit<P> for RsaBlindedEngine<E, R>
where
    E: AsymmetricBlockCipherInit<P, Error = RsaError>,
{
    type Error = RsaError;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), RsaError> {
        self.engine.init(direction, params)
    }
}

/// The blocks of the engine, each processed blinded with a fresh `r` from
/// the random source. Timing is that of the engine's
/// `process_block_blinded`.
impl<E, R> AsymmetricBlockCipher for RsaBlindedEngine<E, R>
where
    E: RsaBlinding,
    R: CryptoRng,
{
    type Error = RsaError;

    /// The input block of the engine. Constant time.
    fn input_block_size(&self) -> usize {
        self.engine.input_block_size()
    }

    /// The output block of the engine. Constant time.
    fn output_block_size(&self) -> usize {
        self.engine.output_block_size()
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, RsaError> {
        self.engine
            .process_block_blinded(input, output, &mut self.rng)
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
    use tc_bigint::{ArrayEncoding, FixedBigUint, Word};

    use super::RsaBlindedEngine;
    use crate::testing::{D, DP, DQ, N, P, Q, Q_INV, hex};
    use crate::{FixedRsaCrtCoreEngine, RsaError, RsaPrivateCrtKeyOwned};

    const WIDE: usize = 2048 / Word::BITS as usize;
    const HALF: usize = 1024 / Word::BITS as usize;
    type U2048 = FixedBigUint<WIDE>;
    type U1024 = FixedBigUint<HALF>;

    fn key() -> RsaPrivateCrtKeyOwned<U2048, U1024> {
        let wide = |text| U2048::from_be(&hex::<256>(text)).unwrap();
        let half = |text| U1024::from_be(&hex::<128>(text)).unwrap();
        RsaPrivateCrtKeyOwned::new(
            wide(N),
            U2048::from(65537u32),
            wide(D),
            half(P),
            half(Q),
            half(DP),
            half(DQ),
            half(Q_INV),
        )
    }

    fn run(engine: &mut impl AsymmetricBlockCipher<Error = RsaError>, input: &[u8]) -> [u8; 256] {
        let mut output = [0; 256];
        assert_eq!(engine.process_block(input, &mut output), Ok(256));
        output
    }

    #[test]
    fn a_blinded_block_comes_out_as_the_unblinded_one() {
        let mut plain = FixedRsaCrtCoreEngine::<WIDE, HALF>::new();
        plain.init(CipherDirection::Decrypt, &key()).unwrap();
        let expected = run(&mut plain, &[0x5a; 255]);
        for seed in 0..4 {
            let mut blinded = RsaBlindedEngine::from_parts(
                FixedRsaCrtCoreEngine::<WIDE, HALF>::new(),
                StdRng::seed_from_u64(seed),
            );
            blinded.init(CipherDirection::Decrypt, &key()).unwrap();
            assert_eq!(run(&mut blinded, &[0x5a; 255]), expected, "{seed}");
            assert_eq!(run(&mut blinded, &[0x5a; 255]), expected, "{seed}");
        }
    }

    #[test]
    fn a_borrowed_source_is_drawn_from_and_given_back() {
        let mut rng = StdRng::seed_from_u64(9);
        let mut blinded = RsaBlindedEngine::<FixedRsaCrtCoreEngine<WIDE, HALF>, _>::new(&mut rng);
        blinded.init(CipherDirection::Encrypt, &key()).unwrap();
        assert_eq!(
            (blinded.input_block_size(), blinded.output_block_size()),
            (255, 256)
        );
        run(&mut blinded, &[0x11; 255]);
        // The borrow ends with the engine, and the source is the caller's again.
        let (_, _) = blinded.into_parts();
        let _: &mut StdRng = &mut rng;
    }

    #[test]
    fn the_range_check_and_the_uninitialized_engine_hold_as_without_blinding() {
        let mut blinded =
            RsaBlindedEngine::<FixedRsaCrtCoreEngine<WIDE, HALF>, _>::new(StdRng::seed_from_u64(1));
        assert_eq!(
            blinded.process_block(&[2], &mut [0; 256]),
            Err(RsaError::NotInitialized)
        );
        blinded.init(CipherDirection::Decrypt, &key()).unwrap();
        assert_eq!(
            blinded.process_block(&[1], &mut [0; 256]),
            Err(RsaError::InputTooSmall)
        );
    }
}
