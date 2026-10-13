//! The RSA engine over [`RsaKey`], on the engine the key and the features
//! suit best.

use alloc::boxed::Box;
use alloc::vec::Vec;

use rand_core::CryptoRng;
use tc_asym_cipher::{
    AsymmetricBlockCipher, AsymmetricBlockCipherInit, AsymmetricKeyParams, CipherDirection,
};
use tc_bigint::{ArrayEncoding, FixedBigUint, PaddedBigUint, Word};
use tc_zeroize::Zeroize;

use crate::block::input_block_size;
use crate::{
    FixedRsaCoreEngine, FixedRsaCrtCoreEngine, PaddedRsaCoreEngine, PaddedRsaCrtCoreEngine,
    RsaBlinding, RsaError, RsaKey, RsaKeyOwned, RsaKeyParams, RsaPrivateCrtKeyOwned,
    RsaPrivateCrtKeyParams,
};

/// The limbs of `bits` bits.
const fn limbs(bits: usize) -> usize {
    bits / Word::BITS as usize
}

const L512: usize = limbs(512);
const L1024: usize = limbs(1024);
const L1536: usize = limbs(1536);
const L2048: usize = limbs(2048);
const L3072: usize = limbs(3072);
const L4096: usize = limbs(4096);

/// The engine a key runs on: a fixed-width one for a modulus of at most
/// 1024, 2048, 3072 or 4096 bits whose primes hold at half the width, a
/// padded one past them, and, with the `rustcrypto` feature, those of
/// `rsa` for the keys it takes.
enum Inner {
    Fixed1024(Box<FixedRsaCoreEngine<L1024>>),
    Fixed1024Crt(Box<FixedRsaCrtCoreEngine<L1024, L512>>),
    Fixed2048(Box<FixedRsaCoreEngine<L2048>>),
    Fixed2048Crt(Box<FixedRsaCrtCoreEngine<L2048, L1024>>),
    Fixed3072(Box<FixedRsaCoreEngine<L3072>>),
    Fixed3072Crt(Box<FixedRsaCrtCoreEngine<L3072, L1536>>),
    Fixed4096(Box<FixedRsaCoreEngine<L4096>>),
    Fixed4096Crt(Box<FixedRsaCrtCoreEngine<L4096, L2048>>),
    Padded(PaddedRsaCoreEngine),
    PaddedCrt(PaddedRsaCrtCoreEngine),
    #[cfg(feature = "rustcrypto")]
    RustCrypto(crate::RsaCoreEngineRustCrypto),
    #[cfg(feature = "rustcrypto")]
    RustCryptoCrt(crate::RsaCrtCoreEngineRustCrypto),
}

/// Runs `$body` on the engine inside `$inner`, whichever it is, as
/// `$engine`.
macro_rules! each {
    ($inner:expr, $engine:ident => $body:expr) => {
        match $inner {
            Inner::Fixed1024($engine) => $body,
            Inner::Fixed1024Crt($engine) => $body,
            Inner::Fixed2048($engine) => $body,
            Inner::Fixed2048Crt($engine) => $body,
            Inner::Fixed3072($engine) => $body,
            Inner::Fixed3072Crt($engine) => $body,
            Inner::Fixed4096($engine) => $body,
            Inner::Fixed4096Crt($engine) => $body,
            Inner::Padded($engine) => $body,
            Inner::PaddedCrt($engine) => $body,
            #[cfg(feature = "rustcrypto")]
            Inner::RustCrypto($engine) => $body,
            #[cfg(feature = "rustcrypto")]
            Inner::RustCryptoCrt($engine) => $body,
        }
    };
}

/// RSA over [`RsaKey`], as Bouncy Castle's `RsaEngine`, on the engine the
/// key and the features suit best, which it picks when it is initialized:
///
/// - with the `rustcrypto` feature, the engines of the RustCrypto `rsa`
///   crate for a public key or a key with its CRT values, of 1024 to 8192
///   bits and a public exponent below 2³³, as `rsa` takes them;
/// - otherwise a fixed-width engine for a modulus of at most 1024, 2048,
///   3072 or 4096 bits, through the CRT when the key holds its values and
///   its primes hold at half the width;
/// - otherwise a padded one, of any width.
///
/// A [`Core`](RsaKey::Core) key is raised by its one exponent, and a
/// [`Crt`](RsaKey::Crt) one through the CRT. The key is checked once, and
/// its values are copied into the integers of the engine picked, at
/// their whole width, and wiped from the copies the conversion makes. The
/// type and its API are the same whichever engine runs; every engine
/// writes the whole of its output block, leading zeros kept.
///
/// When encrypting, it takes an input up to the whole length of the
/// modulus, so long as it is below `n - 1`, as Bouncy Castle's
/// `RsaCoreEngine` does, past the input block, which stays the length any
/// input fits: the engine inside is initialized to decrypt whichever the
/// direction, as RSA raises to the power of the key either way, and the
/// direction only sets the input block. ISO 9796-1 needs it, as its block
/// takes the whole length of the modulus, below it.
///
/// This is an exception to the contract of
/// [`AsymmetricBlockCipher::process_block`], which turns down an input
/// longer than the input block: this engine turns down only an input
/// longer than the modulus, or not below `n - 1`. Code that sizes its
/// input by [`input_block_size`](AsymmetricBlockCipher::input_block_size)
/// is not affected.
///
/// It implements [`RsaBlinding`], so that
/// [`RsaBlindedEngine`](crate::RsaBlindedEngine) blinds a key with its CRT
/// values; as in Bouncy Castle, a key without them is not blinded.
///
/// ```
/// use tc_asym_cipher::{
///     AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection, KeyPairGenerator,
///     KeyPairGeneratorInit,
/// };
/// use tc_rsa_v2::{RsaEngine, RsaKeyGenerationParamsOwned, RsaKeyGenerator};
///
/// // 1. Generate a 2048-bit key pair.
/// let mut generator = RsaKeyGenerator::new();
/// generator.init(RsaKeyGenerationParamsOwned::new(rand::rng()))?;
/// let (public, private) = generator.generate_key_pair()?;
///
/// // 2. Encrypt a block with the public key. Raw RSA is shown here; a real
/// //    message goes through a padding, such as OAEP, first.
/// let message = b"a block of at most 255 bytes";
/// let mut engine = RsaEngine::new();
/// engine.init(CipherDirection::Encrypt, &public)?;
/// let mut ciphertext = [0; 256];
/// engine.process_block(message, &mut ciphertext)?;
///
/// // 3. Decrypt it with the private key, through the CRT.
/// engine.init(CipherDirection::Decrypt, &private)?;
/// let mut plaintext = [0; 256];
/// engine.process_block(&ciphertext, &mut plaintext)?;
/// let recovered = &plaintext[256 - message.len()..];
/// # assert_eq!(recovered, message);
/// # Ok::<(), tc_rsa_v2::RsaError>(())
/// ```
pub struct RsaEngine {
    inner: Option<Inner>,
    direction: CipherDirection,
    bits: u32,
}

impl RsaEngine {
    /// An engine to be initialized before it processes. Constant time.
    pub const fn new() -> Self {
        Self {
            inner: None,
            direction: CipherDirection::Encrypt,
            bits: 0,
        }
    }

    /// The engine inside, once the engine is initialized. Constant time.
    fn inner(&mut self) -> Result<&mut Inner, RsaError> {
        self.inner.as_mut().ok_or(RsaError::NotInitialized)
    }

    /// The name of the engine inside, for the tests to see which ran.
    #[cfg(test)]
    fn engine_name(&self) -> &'static str {
        match self.inner.as_ref() {
            None => "none",
            Some(Inner::Fixed1024(_)) => "Fixed1024",
            Some(Inner::Fixed1024Crt(_)) => "Fixed1024Crt",
            Some(Inner::Fixed2048(_)) => "Fixed2048",
            Some(Inner::Fixed2048Crt(_)) => "Fixed2048Crt",
            Some(Inner::Fixed3072(_)) => "Fixed3072",
            Some(Inner::Fixed3072Crt(_)) => "Fixed3072Crt",
            Some(Inner::Fixed4096(_)) => "Fixed4096",
            Some(Inner::Fixed4096Crt(_)) => "Fixed4096Crt",
            Some(Inner::Padded(_)) => "Padded",
            Some(Inner::PaddedCrt(_)) => "PaddedCrt",
            #[cfg(feature = "rustcrypto")]
            Some(Inner::RustCrypto(_)) => "RustCrypto",
            #[cfg(feature = "rustcrypto")]
            Some(Inner::RustCryptoCrt(_)) => "RustCryptoCrt",
        }
    }
}

/// Through [`new`](RsaEngine::new). Constant time.
impl Default for RsaEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Writes [`ALGO_NAME`](crate::ALGO_NAME) without inspecting key material.
/// Constant time with respect to the key; output timing depends on the
/// formatter.
impl core::fmt::Display for RsaEngine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(crate::ALGO_NAME)
    }
}

/// Checks the key once, picks the engine it suits, copies the key into
/// the integers of that engine and initializes it to decrypt, whichever
/// the direction, which the engine keeps for its input block; fails with
/// `InvalidKey` when the key does not pass, or when the engine picked
/// turns it down. A failed `init` leaves the engine uninitialized.
/// Variable time: only for public values, as the modulus, the public
/// exponent, whether the primes hold at half the width, and the outcome
/// of the checks are; the private values are copied at their whole width.
impl AsymmetricBlockCipherInit<RsaKey> for RsaEngine {
    type Error = RsaError;

    fn init(&mut self, direction: CipherDirection, key: &RsaKey) -> Result<(), RsaError> {
        self.inner = None;
        if !key.validate() {
            return Err(RsaError::InvalidKey);
        }
        let inner = match key {
            RsaKey::Core(key) => core(CipherDirection::Decrypt, key)?,
            RsaKey::Crt(key) => crt(CipherDirection::Decrypt, key)?,
        };
        self.inner = Some(inner);
        self.direction = direction;
        self.bits = key.modulus().bits();
        Ok(())
    }
}

/// The blocks of the engine picked. Constant time where the engine
/// picked is, as each engine tells: in the private exponent and the CRT
/// values, and in variable time in a public exponent.
impl AsymmetricBlockCipher for RsaEngine {
    type Error = RsaError;

    /// `(bits - 1) / 8` bytes when encrypting, the length any input fits,
    /// and `(bits + 7) / 8` when decrypting; zero before initialization.
    /// Constant time.
    fn input_block_size(&self) -> usize {
        self.inner
            .as_ref()
            .map_or(0, |_| input_block_size(self.bits, self.direction))
    }

    /// The output block of the engine picked, `(bits + 7) / 8` bytes;
    /// zero before initialization. Constant time.
    fn output_block_size(&self) -> usize {
        self.inner.as_ref().map_or(
            0,
            |inner| each!(inner, engine => engine.output_block_size()),
        )
    }

    /// Processes the block on the engine picked, as it does, taking up to
    /// the whole length of the modulus in either direction, below
    /// `n - 1`: when encrypting, past the input block, an exception to the
    /// contract of the trait, as the engine tells. Constant time where
    /// that engine is.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, RsaError> {
        each!(self.inner()?, engine => engine.process_block(input, output))
    }
}

/// Blinds the block when the key holds its CRT values, as the engine
/// picked does, and processes it as it is otherwise, as Bouncy Castle's
/// `RsaBlindedEngine` does for a key without them. Constant time where the
/// engine picked is.
impl RsaBlinding for RsaEngine {
    fn process_block_blinded<R: CryptoRng + ?Sized>(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        rng: &mut R,
    ) -> Result<usize, RsaError> {
        match self.inner()? {
            Inner::Fixed1024Crt(engine) => engine.process_block_blinded(input, output, rng),
            Inner::Fixed2048Crt(engine) => engine.process_block_blinded(input, output, rng),
            Inner::Fixed3072Crt(engine) => engine.process_block_blinded(input, output, rng),
            Inner::Fixed4096Crt(engine) => engine.process_block_blinded(input, output, rng),
            Inner::PaddedCrt(engine) => engine.process_block_blinded(input, output, rng),
            #[cfg(feature = "rustcrypto")]
            Inner::RustCryptoCrt(engine) => engine.process_block_blinded(input, output, rng),
            inner => each!(inner, engine => engine.process_block(input, output)),
        }
    }
}

/// The engine of a key raised by its one exponent: that of `rsa` for a
/// public key it takes, with the feature, then a fixed-width one by the
/// size of the modulus, then a padded one. Variable time: only for public
/// values, as the size of the modulus and the public exponent are.
fn core(direction: CipherDirection, key: &RsaKeyOwned<PaddedBigUint>) -> Result<Inner, RsaError> {
    #[cfg(feature = "rustcrypto")]
    if !key.is_private_key() && rustcrypto::takes(key.modulus(), key.exponent()) {
        let mut engine = crate::RsaCoreEngineRustCrypto::new();
        engine.init(direction, &rustcrypto::Public::of(key))?;
        return Ok(Inner::RustCrypto(engine));
    }
    let private = key.is_private_key();
    let (n, exponent) = (key.modulus(), key.exponent());
    macro_rules! try_fixed {
        ($variant:ident, $limbs:expr) => {
            if let (Some(n), Some(exponent)) = (fixed::<$limbs>(n), fixed::<$limbs>(exponent)) {
                let key = RsaKeyOwned::new(private, n, exponent).into_validated();
                let mut engine = Box::new(FixedRsaCoreEngine::<$limbs>::new());
                engine.init(direction, &key)?;
                return Ok(Inner::$variant(engine));
            }
        };
    }
    match n.bits() {
        ..=1024 => try_fixed!(Fixed1024, L1024),
        1025..=2048 => try_fixed!(Fixed2048, L2048),
        2049..=3072 => try_fixed!(Fixed3072, L3072),
        3073..=4096 => try_fixed!(Fixed4096, L4096),
        _ => {}
    }
    let mut engine = PaddedRsaCoreEngine::new();
    engine.init(direction, key)?;
    Ok(Inner::Padded(engine))
}

/// The engine of a key raised through the CRT: that of `rsa` for a key it
/// takes, with the feature, then a fixed-width one by the size of the
/// modulus when the primes and the values modulo them hold at half the
/// width, then a padded one. Variable time: only for public values, as the
/// size of the modulus, the public exponent and whether the values hold
/// are.
fn crt(
    direction: CipherDirection,
    key: &RsaPrivateCrtKeyOwned<PaddedBigUint>,
) -> Result<Inner, RsaError> {
    #[cfg(feature = "rustcrypto")]
    if rustcrypto::takes(key.modulus(), key.public_exponent()) {
        let mut engine = crate::RsaCrtCoreEngineRustCrypto::new();
        engine.init(direction, &rustcrypto::Private::of(key))?;
        return Ok(Inner::RustCryptoCrt(engine));
    }
    macro_rules! try_fixed {
        ($variant:ident, $limbs:expr, $half:expr) => {
            if let Some(key) = fixed_crt::<$limbs, $half>(key) {
                let mut engine = Box::new(FixedRsaCrtCoreEngine::<$limbs, $half>::new());
                engine.init(direction, &key)?;
                return Ok(Inner::$variant(engine));
            }
        };
    }
    match key.modulus().bits() {
        ..=1024 => try_fixed!(Fixed1024Crt, L1024, L512),
        1025..=2048 => try_fixed!(Fixed2048Crt, L2048, L1024),
        2049..=3072 => try_fixed!(Fixed3072Crt, L3072, L1536),
        3073..=4096 => try_fixed!(Fixed4096Crt, L4096, L2048),
        _ => {}
    }
    let mut engine = PaddedRsaCrtCoreEngine::new();
    engine.init(direction, key)?;
    Ok(Inner::PaddedCrt(engine))
}

/// The CRT key at `N` limbs, its primes and the values modulo them at `H`,
/// marked as passed, as the key it comes from passed; `None` when a value
/// does not hold. Constant time in the values, but for whether they hold,
/// which shows.
fn fixed_crt<const N: usize, const H: usize>(
    key: &RsaPrivateCrtKeyOwned<PaddedBigUint>,
) -> Option<RsaPrivateCrtKeyOwned<FixedBigUint<N>, FixedBigUint<H>>> {
    Some(
        RsaPrivateCrtKeyOwned::new(
            fixed(key.modulus())?,
            fixed(key.public_exponent())?,
            fixed(key.exponent())?,
            fixed(key.p())?,
            fixed(key.q())?,
            fixed(key.dp())?,
            fixed(key.dq())?,
            fixed(key.q_inv())?,
        )
        .into_validated(),
    )
}

/// `value` at `N` limbs, through its big-endian bytes at its whole width,
/// which are wiped afterwards; `None` when it does not hold. Constant time
/// in the value, but for whether it holds, which shows.
fn fixed<const N: usize>(value: &PaddedBigUint) -> Option<FixedBigUint<N>> {
    let mut bytes = be_bytes(value);
    let fixed = FixedBigUint::<N>::from_be(&bytes).ok();
    bytes.zeroize();
    fixed
}

/// `value`, big-endian over its whole width. Constant time: the bytes
/// follow the width, not the value.
fn be_bytes(value: &PaddedBigUint) -> Vec<u8> {
    <PaddedBigUint as ArrayEncoding<u8>>::to_be(value)
}

/// The keys of the RustCrypto engines, over `BoxedUint`.
#[cfg(feature = "rustcrypto")]
mod rustcrypto {
    use rsa::{BoxedUint, RsaPublicKey};
    use tc_asym_cipher::AsymmetricKeyParams;
    use tc_bigint::PaddedBigUint;
    use zeroize::Zeroize;

    use super::be_bytes;
    use crate::{RsaKeyOwned, RsaKeyParams, RsaPrivateCrtKeyOwned, RsaPrivateCrtKeyParams};

    /// The bits of the largest public exponent `rsa` takes.
    const EXPONENT_BITS: u32 = 33;

    /// Whether `rsa` takes a key of `modulus` and the public `exponent`:
    /// a modulus of 1024 bits, the least `rsa` generates, to the most it
    /// takes, and an exponent of at most 33 bits. Variable time: only for
    /// public values.
    pub(super) fn takes(modulus: &PaddedBigUint, exponent: &PaddedBigUint) -> bool {
        (1024..=RsaPublicKey::MAX_SIZE as u32).contains(&modulus.bits())
            && exponent.bits() <= EXPONENT_BITS
    }

    /// `value` at its whole width, through its big-endian bytes, which are
    /// wiped afterwards. Constant time: the bytes follow the width.
    fn boxed(value: &PaddedBigUint) -> BoxedUint {
        let mut bytes = be_bytes(value);
        let boxed = BoxedUint::from_be_slice_truncated(&bytes, bytes.len() as u32 * 8);
        bytes.zeroize();
        boxed
    }

    /// A public key over `BoxedUint`, passed, as the key it comes from
    /// was.
    pub(super) struct Public {
        modulus: BoxedUint,
        exponent: BoxedUint,
    }

    impl Public {
        /// The public `key`, copied. Constant time.
        pub(super) fn of(key: &RsaKeyOwned<PaddedBigUint>) -> Self {
            Self {
                modulus: boxed(key.modulus()),
                exponent: boxed(key.exponent()),
            }
        }
    }

    /// Not private. Constant time.
    impl AsymmetricKeyParams for Public {
        fn is_private_key(&self) -> bool {
            false
        }
    }

    /// The values, passed. Constant time.
    impl RsaKeyParams<BoxedUint> for Public {
        fn modulus(&self) -> &BoxedUint {
            &self.modulus
        }

        fn exponent(&self) -> &BoxedUint {
            &self.exponent
        }

        fn validate(&self) -> bool {
            true
        }
    }

    /// A private key with its CRT values over `BoxedUint`, passed, as the
    /// key it comes from was, and wiped on drop.
    pub(super) struct Private {
        modulus: BoxedUint,
        public_exponent: BoxedUint,
        private_exponent: BoxedUint,
        p: BoxedUint,
        q: BoxedUint,
        dp: BoxedUint,
        dq: BoxedUint,
        q_inv: BoxedUint,
    }

    impl Private {
        /// The private `key`, copied at the whole width of each value.
        /// Constant time.
        pub(super) fn of(key: &RsaPrivateCrtKeyOwned<PaddedBigUint>) -> Self {
            Self {
                modulus: boxed(key.modulus()),
                public_exponent: boxed(key.public_exponent()),
                private_exponent: boxed(key.exponent()),
                p: boxed(key.p()),
                q: boxed(key.q()),
                dp: boxed(key.dp()),
                dq: boxed(key.dq()),
                q_inv: boxed(key.q_inv()),
            }
        }
    }

    /// Wipes every value. Constant time.
    impl Drop for Private {
        fn drop(&mut self) {
            for value in [
                &mut self.modulus,
                &mut self.public_exponent,
                &mut self.private_exponent,
                &mut self.p,
                &mut self.q,
                &mut self.dp,
                &mut self.dq,
                &mut self.q_inv,
            ] {
                value.zeroize();
            }
        }
    }

    /// Private. Constant time.
    impl AsymmetricKeyParams for Private {
        fn is_private_key(&self) -> bool {
            true
        }
    }

    /// The modulus and `d`, passed. Constant time.
    impl RsaKeyParams<BoxedUint> for Private {
        fn modulus(&self) -> &BoxedUint {
            &self.modulus
        }

        fn exponent(&self) -> &BoxedUint {
            &self.private_exponent
        }

        fn validate(&self) -> bool {
            true
        }
    }

    /// The CRT values. Constant time.
    impl RsaPrivateCrtKeyParams<BoxedUint> for Private {
        fn public_exponent(&self) -> &BoxedUint {
            &self.public_exponent
        }

        fn p(&self) -> &BoxedUint {
            &self.p
        }

        fn q(&self) -> &BoxedUint {
            &self.q
        }

        fn dp(&self) -> &BoxedUint {
            &self.dp
        }

        fn dq(&self) -> &BoxedUint {
            &self.dq
        }

        fn q_inv(&self) -> &BoxedUint {
            &self.q_inv
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;

    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use tc_asym_cipher::{
        AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection, KeyPairGenerator,
        KeyPairGeneratorInit,
    };
    use tc_bigint::{ArrayEncoding, PaddedBigUint};

    use super::RsaEngine;
    use crate::{
        PaddedRsaCoreEngine, PaddedRsaCrtCoreEngine, RsaBlindedEngine, RsaError, RsaKey,
        RsaKeyGenerationParamsOwned, RsaKeyGenerator, RsaKeyOwned, RsaKeyParams,
    };

    fn int(value: u32) -> PaddedBigUint {
        PaddedBigUint::from(value)
    }

    /// `2^bits - 1`, odd and of `bits` bits.
    fn all_ones(bits: u32) -> PaddedBigUint {
        let length = bits.div_ceil(8) as usize;
        let mut bytes = vec![0xffu8; length];
        bytes[0] >>= length as u32 * 8 - bits;
        let Ok(value) = PaddedBigUint::from_be(&bytes);
        value
    }

    /// A public key of `bits` bits, marked as passed, which only the
    /// choice of the engine reads.
    fn public_of(bits: u32) -> RsaKey {
        RsaKey::from(RsaKeyOwned::new(false, all_ones(bits), int(3)).into_validated())
    }

    /// A key with CRT values of a `bits`-bit modulus and primes of `p` and
    /// `q` bits, marked as passed, which only the choice of the engine
    /// reads.
    #[cfg(not(feature = "rustcrypto"))]
    fn crt_of(bits: u32, p: u32, q: u32) -> RsaKey {
        let (p, q) = (all_ones(p), all_ones(q));
        RsaKey::from(
            crate::RsaPrivateCrtKeyOwned::new(
                all_ones(bits),
                int(3),
                all_ones(bits - 2),
                p.clone(),
                q.clone(),
                p.clone() - 2u32,
                q - 2u32,
                p - 3u32,
            )
            .into_validated(),
        )
    }

    fn engine_for(key: &RsaKey) -> &'static str {
        let mut engine = RsaEngine::new();
        engine.init(CipherDirection::Encrypt, key).unwrap();
        engine.engine_name()
    }

    #[test]
    fn a_public_key_runs_on_the_fixed_width_that_holds_it_or_padded_past_them() {
        let rustcrypto = cfg!(feature = "rustcrypto");
        for (bits, fixed) in [
            (12, "Fixed1024"),
            (1024, "Fixed1024"),
            (1025, "Fixed2048"),
            (2048, "Fixed2048"),
            (2049, "Fixed3072"),
            (3072, "Fixed3072"),
            (3073, "Fixed4096"),
            (4096, "Fixed4096"),
            (4097, "Padded"),
            (8193, "Padded"),
        ] {
            let expected = if rustcrypto && (1024..=8192).contains(&bits) {
                "RustCrypto"
            } else {
                fixed
            };
            assert_eq!(engine_for(&public_of(bits)), expected, "{bits}");
        }
    }

    #[cfg(not(feature = "rustcrypto"))]
    #[test]
    fn a_crt_key_runs_on_the_fixed_width_its_primes_hold_at_half_of() {
        for (bits, expected) in [
            (1024, "Fixed1024Crt"),
            (2048, "Fixed2048Crt"),
            (3072, "Fixed3072Crt"),
            (4096, "Fixed4096Crt"),
            (4098, "PaddedCrt"),
        ] {
            let half = bits / 2;
            assert_eq!(engine_for(&crt_of(bits, half, half)), expected, "{bits}");
        }
        // Primes that do not hold at half the width fall back to padded.
        assert_eq!(engine_for(&crt_of(1024, 600, 424)), "PaddedCrt");
    }

    #[test]
    fn a_private_key_without_crt_values_runs_on_an_engine_of_this_crate() {
        let key = RsaKey::from(RsaKeyOwned::new(true, all_ones(2048), int(5)).into_validated());
        assert_eq!(engine_for(&key), "Fixed2048");
    }

    /// The textbook key, p = 61 and q = 53, marked as checked, as its
    /// modulus has small factors.
    fn textbook(private: bool) -> RsaKey {
        let exponent = if private { 2753 } else { 17 };
        RsaKey::from(RsaKeyOwned::new(private, int(3233), int(exponent)).into_validated())
    }

    #[test]
    fn the_textbook_key_encrypts_65_to_2790_and_back() {
        let mut engine = RsaEngine::new();
        let mut output = [0; 2];
        engine
            .init(CipherDirection::Encrypt, &textbook(false))
            .unwrap();
        assert_eq!(engine.process_block(&[65], &mut output), Ok(2));
        assert_eq!(output, 2790u16.to_be_bytes());
        engine
            .init(CipherDirection::Decrypt, &textbook(true))
            .unwrap();
        assert_eq!(engine.process_block(&output.clone(), &mut output), Ok(2));
        assert_eq!(output, [0, 65]);
    }

    fn process(engine: &mut impl AsymmetricBlockCipher<Error = RsaError>, input: &[u8]) -> Vec<u8> {
        let mut output = vec![0; engine.output_block_size()];
        engine.process_block(input, &mut output).unwrap();
        output
    }

    #[test]
    fn a_generated_pair_gives_what_the_padded_engines_give() {
        let mut generator = RsaKeyGenerator::new();
        let params = RsaKeyGenerationParamsOwned::new(StdRng::seed_from_u64(3)).with_strength(1024);
        generator.init(params).unwrap();
        let (public, private) = generator.generate_key_pair().unwrap();
        let RsaKey::Crt(crt) = &private else {
            panic!("a generated private key holds its CRT values");
        };
        let message = [0x5a; 127];

        let mut engine = RsaEngine::new();
        engine.init(CipherDirection::Encrypt, &public).unwrap();
        let ciphertext = process(&mut engine, &message);
        let mut reference = PaddedRsaCoreEngine::new();
        reference.init(CipherDirection::Encrypt, &public).unwrap();
        assert_eq!(process(&mut reference, &message), ciphertext);

        engine.init(CipherDirection::Decrypt, &private).unwrap();
        let plaintext = process(&mut engine, &ciphertext);
        assert_eq!(&plaintext[1..], &message[..]);
        let mut reference = PaddedRsaCrtCoreEngine::new();
        reference.init(CipherDirection::Decrypt, crt).unwrap();
        assert_eq!(process(&mut reference, &ciphertext), plaintext);

        // The same key without its CRT values, raised by `d` alone.
        let plain = RsaKey::from(
            RsaKeyOwned::new(true, crt.modulus().clone(), crt.exponent().clone()).into_validated(),
        );
        engine.init(CipherDirection::Decrypt, &plain).unwrap();
        assert_eq!(engine.engine_name(), "Fixed1024");
        assert_eq!(process(&mut engine, &ciphertext), plaintext);

        // Blinded, with the CRT values and without them.
        for key in [&private, &plain] {
            let mut blinded =
                RsaBlindedEngine::from_parts(RsaEngine::new(), StdRng::seed_from_u64(4));
            blinded.init(CipherDirection::Decrypt, key).unwrap();
            assert_eq!(process(&mut blinded, &ciphertext), plaintext);
        }
    }

    #[test]
    fn an_engine_not_yet_initialized_or_given_a_bad_key_processes_nothing() {
        let mut engine = RsaEngine::new();
        assert_eq!(
            (engine.input_block_size(), engine.output_block_size()),
            (0, 0)
        );
        assert_eq!(
            engine.process_block(&[2], &mut [0; 2]),
            Err(RsaError::NotInitialized)
        );
        engine
            .init(CipherDirection::Encrypt, &textbook(false))
            .unwrap();
        // Not marked as passed, the textbook modulus fails its checks.
        let unchecked = RsaKey::from(RsaKeyOwned::new(false, int(3233), int(17)));
        assert_eq!(
            engine.init(CipherDirection::Encrypt, &unchecked),
            Err(RsaError::InvalidKey)
        );
        assert_eq!(
            engine.process_block(&[2], &mut [0; 2]),
            Err(RsaError::NotInitialized)
        );
    }

    #[test]
    fn encrypting_takes_an_input_of_the_whole_modulus_below_n_less_one() {
        let mut engine = RsaEngine::new();
        engine
            .init(CipherDirection::Encrypt, &textbook(false))
            .unwrap();
        // The input block stays the length any input fits.
        assert_eq!(
            (engine.input_block_size(), engine.output_block_size()),
            (1, 2)
        );
        let mut output = [0; 2];
        assert_eq!(
            engine.process_block(&3231u16.to_be_bytes(), &mut output),
            Ok(2)
        );
        for input in [&3232u16.to_be_bytes()[..], &[0, 0, 2]] {
            assert_eq!(
                engine.process_block(input, &mut output),
                Err(RsaError::InputTooLarge),
                "{input:?}"
            );
        }
    }

    #[test]
    fn the_engine_is_named_rsa() {
        assert_eq!(RsaEngine::new().to_string(), "RSA");
    }
}
