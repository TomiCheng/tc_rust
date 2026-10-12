//! The RSA operation with the CRT, as Bouncy Castle's `RsaCoreEngine` runs
//! it for a CRT key, over `FixedBigUint`, the modulus at `N` limbs and the
//! primes at `H`.

use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
use tc_bigint::{ArrayEncoding, FixedBigUint, Limb, LimbArray};
use tc_modular::{FixedMontyForm, FixedMontyParams, Odd};
use tc_zeroize::{Zeroize, Zeroizing};

use crate::block::{input_block_size, output_block_size, write_be};
use crate::{RsaError, RsaPrivateCrtKeyParams};

/// What an engine keeps from its initialization: the modulus and `n - 1`
/// for the range check of the input, the public exponent and the
/// Montgomery parameters of `n` for the check of the result, the primes at
/// the width of the modulus for the reduction of the input and the
/// recombination, their Montgomery parameters, the CRT values, the size of
/// the modulus in bits, and the direction. The secret values are wiped on
/// drop.
struct CrtKey<const N: usize, const H: usize> {
    modulus_less_one: FixedBigUint<N>,
    public_exponent: FixedBigUint<N>,
    params_n: FixedMontyParams<N>,
    wide_p: FixedBigUint<N>,
    wide_q: FixedBigUint<N>,
    params_p: FixedMontyParams<H>,
    params_q: FixedMontyParams<H>,
    dp: FixedBigUint<H>,
    dq: FixedBigUint<H>,
    q_inv: FixedBigUint<H>,
    bits: u32,
    direction: CipherDirection,
}

/// Wipes the primes, their parameters and the CRT values. Constant time.
impl<const N: usize, const H: usize> Drop for CrtKey<N, H> {
    fn drop(&mut self) {
        self.wide_p.zeroize();
        self.wide_q.zeroize();
        self.params_p.zeroize();
        self.params_q.zeroize();
        self.dp.zeroize();
        self.dq.zeroize();
        self.q_inv.zeroize();
    }
}

/// The RSA operation with the CRT over [`FixedBigUint`], the modulus at `N`
/// limbs and the primes at `H`, as Bouncy Castle's `RsaCoreEngine` runs it
/// for a CRT key: `x^d mod n` as two powers modulo the primes, at `H`
/// limbs, recombined, and checked by raising the result back to `e`, which
/// turns down a result a fault has spoiled, as Lenstra's attack on the CRT
/// needs. `H` must be at most `N`, which the build checks. The key is
/// copied in at initialization, and nothing is allocated. The blocks are as
/// those of [`FixedRsaCoreEngine`](crate::FixedRsaCoreEngine): the output always
/// takes the full length of the modulus, leading zeros kept.
///
/// From a new key to a block encrypted with the public key and decrypted
/// through the CRT; key generation takes the `alloc` feature, while the
/// engines do not:
///
/// ```
/// # #[cfg(feature = "alloc")] {
/// use tc_asym_cipher::{
///     AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection, KeyPairGenerator,
///     KeyPairGeneratorInit,
/// };
/// use tc_bigint::{FixedBigUint, Word};
/// use tc_rsa_v2::{
///     FixedRsaCoreEngine, FixedRsaCrtCoreEngine, RsaKeyGenerationParamsOwned, RsaKeyPairGenerator,
/// };
///
/// // A 2048-bit modulus, with its primes at half that width, which is what
/// // makes the CRT fast; the widths follow from the limbs.
/// type U2048 = FixedBigUint<{ 2048 / Word::BITS as usize }>;
/// type U1024 = FixedBigUint<{ 1024 / Word::BITS as usize }>;
///
/// // 1. Generate a key pair, its primes and CRT values at 1024 bits.
/// let mut generator = RsaKeyPairGenerator::<U2048, U1024>::new();
/// generator.init(RsaKeyGenerationParamsOwned::new(rand::rng()))?;
/// let (public, private) = generator.generate_key_pair()?;
///
/// // 2. Encrypt a block with the public key, which has no CRT. Raw RSA is
/// //    shown here; a real message goes through a padding, such as OAEP,
/// //    first.
/// let message = b"a block of at most 255 bytes";
/// let mut encrypt = FixedRsaCoreEngine::new();
/// encrypt.init(CipherDirection::Encrypt, &public)?;
/// let mut ciphertext = [0; 256];
/// encrypt.process_block(message, &mut ciphertext)?;
///
/// // 3. Decrypt it through the CRT with the private key. A result that a
/// //    fault spoils fails with `FaultyDecryptionOrSigning` instead.
/// let mut decrypt = FixedRsaCrtCoreEngine::new();
/// decrypt.init(CipherDirection::Decrypt, &private)?;
/// let mut plaintext = [0; 256];
/// decrypt.process_block(&ciphertext, &mut plaintext)?;
/// let recovered = &plaintext[256 - message.len()..];
/// # }
/// # Ok::<(), tc_rsa_v2::RsaError>(())
/// ```
pub struct FixedRsaCrtCoreEngine<const N: usize, const H: usize> {
    key: Option<CrtKey<N, H>>,
}

impl<const N: usize, const H: usize> FixedRsaCrtCoreEngine<N, H> {
    /// An engine to be initialized before it processes. Fails to build when
    /// `H` is past `N`. Constant time.
    pub const fn new() -> Self {
        const { assert!(H <= N, "the primes must not be wider than the modulus") };
        Self { key: None }
    }

    /// The key, once the engine is initialized. Constant time.
    fn key(&self) -> Result<&CrtKey<N, H>, RsaError> {
        self.key.as_ref().ok_or(RsaError::NotInitialized)
    }
}

/// Through [`new`](FixedRsaCrtCoreEngine::new). Constant time.
impl<const N: usize, const H: usize> Default for FixedRsaCrtCoreEngine<N, H> {
    fn default() -> Self {
        Self::new()
    }
}

/// Copies the key in, once [`validate`](crate::RsaKeyParams::validate)
/// passes it, and works out the Montgomery parameters of `n`, `p` and `q`;
/// fails with `InvalidKey` when the key does not pass, or when the modulus
/// or a prime is even, which a Montgomery form cannot take. Variable time:
/// only for public values, as the modulus and the outcome of the checks
/// are; the parameters of the primes are worked out in constant time.
impl<P, const N: usize, const H: usize> AsymmetricBlockCipherInit<P> for FixedRsaCrtCoreEngine<N, H>
where
    P: RsaPrivateCrtKeyParams<FixedBigUint<N>, FixedBigUint<H>>,
{
    type Error = RsaError;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), RsaError> {
        if !params.validate() {
            return Err(RsaError::InvalidKey);
        }
        let modulus = params.modulus();
        let (p, q) = (params.p(), params.q());
        self.key = Some(CrtKey {
            modulus_less_one: modulus.clone() - 1u32,
            public_exponent: params.public_exponent().clone(),
            params_n: FixedMontyParams::new(Odd::new(modulus.clone()).ok_or(RsaError::InvalidKey)?),
            wide_p: resized(p),
            wide_q: resized(q),
            params_p: FixedMontyParams::new(Odd::new(p.clone()).ok_or(RsaError::InvalidKey)?),
            params_q: FixedMontyParams::new(Odd::new(q.clone()).ok_or(RsaError::InvalidKey)?),
            dp: params.dp().clone(),
            dq: params.dq().clone(),
            q_inv: params.q_inv().clone(),
            bits: modulus.bits(),
            direction,
        });
        Ok(())
    }
}

/// Reads the input as a big-endian integer `x` with `1 < x < n - 1`, as
/// Bouncy Castle does, and computes `m = x^d mod n` through the CRT:
/// `x mod p` and `x mod q` by long division at `N` limbs, cut to `H`, each
/// raised to its CRT exponent in Montgomery form at `H` limbs, then
/// `h = (mP - mQ) · qInv mod p` and `m = h · q + mQ` at `N` limbs. It then
/// checks that `m^e mod n` is `x` again, and fails with
/// `FaultyDecryptionOrSigning` otherwise, writing nothing. Constant time in
/// the secret values; the check raises to the public `e` from its top bit
/// only, in variable time, as `e` is public, and the outcome of the range
/// check and of the check of the result show in the error. There is no
/// blinding: a caller who needs it blinds the input, as Bouncy Castle's
/// `RsaBlindedEngine` does.
impl<const N: usize, const H: usize> AsymmetricBlockCipher for FixedRsaCrtCoreEngine<N, H> {
    type Error = RsaError;

    /// `(bits - 1) / 8` bytes when encrypting, which here is signing with
    /// the private key, and `(bits + 7) / 8` when decrypting; zero before
    /// initialization. Constant time.
    fn input_block_size(&self) -> usize {
        self.key
            .as_ref()
            .map_or(0, |key| input_block_size(key.bits, key.direction))
    }

    /// `(bits + 7) / 8` bytes in both directions; zero before
    /// initialization. Constant time.
    fn output_block_size(&self) -> usize {
        self.key
            .as_ref()
            .map_or(0, |key| output_block_size(key.bits))
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, RsaError> {
        let key = self.key()?;
        if input.len() > self.input_block_size() {
            return Err(RsaError::InputTooLarge);
        }
        let length = self.output_block_size();
        if output.len() < length {
            return Err(RsaError::OutputTooShort);
        }
        let x =
            Zeroizing::new(FixedBigUint::<N>::from_be(input).map_err(|_| RsaError::InputTooLarge)?);
        if x.bits() <= 1 {
            return Err(RsaError::InputTooSmall);
        }
        if *x >= key.modulus_less_one {
            return Err(RsaError::InputTooLarge);
        }

        let m_p = Zeroizing::new(power(&x, &key.wide_p, &key.params_p, &key.dp));
        let m_q = Zeroizing::new(power(&x, &key.wide_q, &key.params_q, &key.dq));
        let m_q_in_p = Zeroizing::new(FixedMontyForm::new(&m_q.retrieve(), key.params_p.clone()));
        let q_inv = Zeroizing::new(FixedMontyForm::new(&key.q_inv, key.params_p.clone()));
        let h = Zeroizing::new(&(&*m_p - &*m_q_in_p) * &*q_inv);
        let mut m = Zeroizing::new(resized::<H, N>(&h.retrieve()));
        *m *= &key.wide_q;
        *m += &resized::<H, N>(&m_q.retrieve());

        let check = FixedMontyForm::new(&m, key.params_n.clone()).pow_vartime(&key.public_exponent);
        if check.retrieve() != *x {
            return Err(RsaError::FaultyDecryptionOrSigning);
        }
        write_be(&*m, &mut output[..length]);
        Ok(length)
    }
}

/// `(x mod prime)^exponent mod prime`, in Montgomery form at the `H` limbs
/// of the prime: the residue by long division at `N` limbs, cut to `H`.
/// Constant time.
fn power<const N: usize, const H: usize>(
    x: &FixedBigUint<N>,
    wide_prime: &FixedBigUint<N>,
    params: &FixedMontyParams<H>,
    exponent: &FixedBigUint<H>,
) -> FixedMontyForm<H> {
    let residue = Zeroizing::new(resized::<N, H>(&(x % wide_prime)));
    FixedMontyForm::new(&residue, params.clone()).pow(exponent)
}

/// `value` at `K` limbs: zero limbs added, or the limbs past `K`, which
/// must be zero, taken off. Constant time.
fn resized<const M: usize, const K: usize>(value: &FixedBigUint<M>) -> FixedBigUint<K> {
    let mut limbs = [Limb::new(0); K];
    let kept = M.min(K);
    limbs[..kept].copy_from_slice(&value.as_limbs()[..kept]);
    FixedBigUint::new(LimbArray::new(limbs))
}

#[cfg(test)]
mod tests {
    use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
    use tc_bigint::{ArrayEncoding, FixedBigUint, Word};

    use super::FixedRsaCrtCoreEngine;
    use crate::testing::{D, DP, DQ, N, P, Q, Q_INV, hex};
    use crate::{FixedRsaCoreEngine, RsaError, RsaKeyOwned, RsaPrivateCrtKeyOwned};

    const WIDE: usize = 2048 / Word::BITS as usize;
    const HALF: usize = 1024 / Word::BITS as usize;
    type U2048 = FixedBigUint<WIDE>;
    type U1024 = FixedBigUint<HALF>;

    fn wide(text: &str) -> U2048 {
        U2048::from_be(&hex::<256>(text)).unwrap()
    }

    fn half(text: &str) -> U1024 {
        U1024::from_be(&hex::<128>(text)).unwrap()
    }

    /// The first key of Wycheproof's `rsa_pkcs1_2048_test.json`, with `p`
    /// and `dP` as given.
    fn wycheproof(p: U1024, dp: U1024) -> RsaPrivateCrtKeyOwned<U2048, U1024> {
        RsaPrivateCrtKeyOwned::new(
            wide(N),
            U2048::from(65537u32),
            wide(D),
            p,
            half(Q),
            dp,
            half(DQ),
            half(Q_INV),
        )
    }

    fn engine(key: &RsaPrivateCrtKeyOwned<U2048, U1024>) -> FixedRsaCrtCoreEngine<WIDE, HALF> {
        let mut engine = FixedRsaCrtCoreEngine::new();
        engine.init(CipherDirection::Decrypt, key).unwrap();
        engine
    }

    fn process(
        engine: &mut impl AsymmetricBlockCipher<Error = RsaError>,
        input: &[u8],
    ) -> Result<[u8; 256], RsaError> {
        let mut output = [0; 256];
        assert_eq!(engine.process_block(input, &mut output)?, 256);
        Ok(output)
    }

    #[test]
    fn the_crt_agrees_with_the_plain_power_of_d() {
        let mut crt = engine(&wycheproof(half(P), half(DP)));
        let mut plain = FixedRsaCoreEngine::new();
        plain
            .init(
                CipherDirection::Decrypt,
                &RsaKeyOwned::new(true, wide(N), wide(D)),
            )
            .unwrap();
        for fill in [0x02u8, 0x5a, 0xb3] {
            let input = [fill; 255];
            assert_eq!(
                process(&mut crt, &input),
                process(&mut plain, &input),
                "{fill:#x}"
            );
        }
    }

    #[test]
    fn a_message_encrypted_with_the_public_key_comes_back() {
        let mut encrypt = FixedRsaCoreEngine::new();
        encrypt
            .init(
                CipherDirection::Encrypt,
                &RsaKeyOwned::new(false, wide(N), U2048::from(65537u32)),
            )
            .unwrap();
        let mut message = [0x42; 255];
        message[0] = 0x01;
        let ciphertext = process(&mut encrypt, &message).unwrap();
        let plaintext = process(&mut engine(&wycheproof(half(P), half(DP))), &ciphertext).unwrap();
        assert_eq!(plaintext[0], 0);
        assert_eq!(&plaintext[1..], &message[..]);
    }

    #[test]
    fn a_wrong_crt_value_is_caught_by_the_check_of_the_result() {
        let mut engine = engine(&wycheproof(half(P), half(DP) + 2u32));
        let mut output = [0; 256];
        assert_eq!(
            engine.process_block(&[0x5a; 255], &mut output),
            Err(RsaError::FaultyDecryptionOrSigning)
        );
        assert_eq!(output, [0; 256]);
    }

    #[test]
    fn an_even_prime_is_turned_down() {
        let key = wycheproof(half(P) + 1u32, half(DP));
        let mut engine = FixedRsaCrtCoreEngine::<WIDE, HALF>::new();
        assert_eq!(
            engine.init(CipherDirection::Decrypt, &key),
            Err(RsaError::InvalidKey)
        );
    }

    #[test]
    fn inputs_outside_two_to_n_less_two_are_turned_down() {
        let mut engine = engine(&wycheproof(half(P), half(DP)));
        let mut output = [0; 256];
        assert_eq!(
            engine.process_block(&[1], &mut output),
            Err(RsaError::InputTooSmall)
        );
        assert_eq!(
            engine.process_block(&hex::<256>(N), &mut output),
            Err(RsaError::InputTooLarge)
        );
        assert_eq!(
            engine.process_block(&[2], &mut [0; 255]),
            Err(RsaError::OutputTooShort)
        );
    }

    #[test]
    fn an_engine_not_yet_initialized_processes_nothing() {
        let mut engine = FixedRsaCrtCoreEngine::<WIDE, HALF>::new();
        assert_eq!(
            (engine.input_block_size(), engine.output_block_size()),
            (0, 0)
        );
        assert_eq!(
            engine.process_block(&[2], &mut [0; 2]),
            Err(RsaError::NotInitialized)
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn it_agrees_with_the_padded_crt_engine() {
        use tc_bigint::PaddedBigUint;

        let padded_wide = |text: &str| PaddedBigUint::from_be(&hex::<256>(text)).unwrap();
        let padded_half = |text: &str| PaddedBigUint::from_be(&hex::<128>(text)).unwrap();
        let key = RsaPrivateCrtKeyOwned::new(
            padded_wide(N),
            PaddedBigUint::from(65537u32),
            padded_wide(D),
            padded_half(P),
            padded_half(Q),
            padded_half(DP),
            padded_half(DQ),
            padded_half(Q_INV),
        );
        let mut padded_engine = crate::PaddedRsaCrtCoreEngine::new();
        padded_engine.init(CipherDirection::Decrypt, &key).unwrap();
        let mut fixed = engine(&wycheproof(half(P), half(DP)));
        let input = [0x77; 256 - 1];
        assert_eq!(
            process(&mut fixed, &input),
            process(&mut padded_engine, &input)
        );
    }
}
