//! The RSA operation with the CRT, as Bouncy Castle's `RsaCoreEngine` runs
//! it for a CRT key, over `PaddedBigUint`.

use alloc::vec;

use rand_core::CryptoRng;
use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
use tc_bigint::{ArrayEncoding, Limb, PaddedBigUint, RandomRange};
use tc_modular::{ModMul, ModPow, ModSub, NonZero, Odd, PaddedMontyForm, PaddedMontyParams};
use tc_zeroize::{Zeroize, Zeroizing};

use crate::block::{input_block_size, output_block_size, write_be};
use crate::{RsaBlinding, RsaError, RsaPrivateCrtKeyParams};

/// What an engine keeps from its initialization: the modulus and `n - 1`
/// for the range check of the input, the public exponent at its own width
/// for the check of the result, the CRT values at the widths they came in,
/// the size of the modulus in bits, and the direction. The secret values
/// are wiped on drop.
struct CrtKey {
    modulus: NonZero<PaddedBigUint>,
    modulus_less_one: PaddedBigUint,
    public_exponent: PaddedBigUint,
    params_n: PaddedMontyParams,
    p: NonZero<PaddedBigUint>,
    q: NonZero<PaddedBigUint>,
    dp: PaddedBigUint,
    dq: PaddedBigUint,
    q_inv: PaddedBigUint,
    bits: u32,
    direction: CipherDirection,
}

/// Wipes the CRT values, the primes by taking them out of their
/// `NonZero`. Constant time: the widths are public.
impl Drop for CrtKey {
    fn drop(&mut self) {
        for prime in [&mut self.p, &mut self.q] {
            let one = NonZero::new(PaddedBigUint::from(1u8)).expect("one is not zero");
            core::mem::replace(prime, one).into_inner().zeroize();
        }
        self.dp.zeroize();
        self.dq.zeroize();
        self.q_inv.zeroize();
    }
}

/// The RSA operation with the CRT over [`PaddedBigUint`], as Bouncy
/// Castle's `RsaCoreEngine` runs it for a CRT key: `x^d mod n` as two
/// powers modulo the primes, at their width, then recombined, and checked
/// by raising the result back to `e`, which turns down a result a fault
/// has spoiled, as Lenstra's attack on the CRT needs. The key is copied in
/// at initialization. The blocks are as those of
/// [`PaddedRsaCoreEngine`](crate::PaddedRsaCoreEngine): the output always takes the
/// full length of the modulus, leading zeros kept.
///
/// From a new key to a block encrypted with the public key and decrypted
/// through the CRT:
///
/// ```
/// use tc_asym_cipher::{
///     AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection, KeyPairGenerator,
///     KeyPairGeneratorInit,
/// };
/// use tc_bigint::PaddedBigUint;
/// use tc_rsa_v2::{
///     PaddedRsaCoreEngine, PaddedRsaCrtCoreEngine, RsaKeyGenerationParamsOwned,
///     RsaKeyPairGenerator,
/// };
///
/// // 1. Generate a key pair: a 2048-bit modulus and the public exponent
/// //    65537; the primes and the CRT values come at half the width.
/// let mut generator = RsaKeyPairGenerator::<PaddedBigUint>::new();
/// generator.init(RsaKeyGenerationParamsOwned::new(rand::rng()))?;
/// let (public, private) = generator.generate_key_pair()?;
///
/// // 2. Encrypt a block with the public key, which has no CRT. Raw RSA is
/// //    shown here; a real message goes through a padding, such as OAEP,
/// //    first.
/// let message = b"a block shorter than the modulus";
/// let mut encrypt = PaddedRsaCoreEngine::new();
/// encrypt.init(CipherDirection::Encrypt, &public)?;
/// let mut ciphertext = vec![0; encrypt.output_block_size()];
/// encrypt.process_block(message, &mut ciphertext)?;
///
/// // 3. Decrypt it through the CRT with the private key. A result that a
/// //    fault spoils fails with `FaultyDecryptionOrSigning` instead.
/// let mut decrypt = PaddedRsaCrtCoreEngine::new();
/// decrypt.init(CipherDirection::Decrypt, &private)?;
/// let mut plaintext = vec![0; decrypt.output_block_size()];
/// decrypt.process_block(&ciphertext, &mut plaintext)?;
/// let recovered = &plaintext[plaintext.len() - message.len()..];
/// # Ok::<(), tc_rsa_v2::RsaError>(())
/// ```
pub struct PaddedRsaCrtCoreEngine {
    key: Option<CrtKey>,
}

impl PaddedRsaCrtCoreEngine {
    /// An engine to be initialized before it processes. Constant time.
    pub const fn new() -> Self {
        Self { key: None }
    }

    /// The key, once the engine is initialized. Constant time.
    fn key(&self) -> Result<&CrtKey, RsaError> {
        self.key.as_ref().ok_or(RsaError::NotInitialized)
    }
}

/// Through [`new`](PaddedRsaCrtCoreEngine::new). Constant time.
impl Default for PaddedRsaCrtCoreEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Writes [`ALGO_NAME`](crate::ALGO_NAME) without inspecting key material.
/// Constant time with respect to the key; output timing depends on the
/// formatter.
impl core::fmt::Display for PaddedRsaCrtCoreEngine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(crate::ALGO_NAME)
    }
}

/// Copies the key in, once [`validate`](crate::RsaKeyParams::validate)
/// passes it, and fails with `InvalidKey` otherwise. The public exponent is
/// kept at the width of its own bits, so that the check of a result costs
/// the few squarings of `e` rather than those of the width of the modulus.
/// Variable time: only for public values, as the modulus, the public
/// exponent and the outcome of the checks are; the secret values are only
/// copied, and read for zero.
impl<P> AsymmetricBlockCipherInit<P> for PaddedRsaCrtCoreEngine
where
    P: RsaPrivateCrtKeyParams<PaddedBigUint>,
{
    type Error = RsaError;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), RsaError> {
        if !params.validate() {
            return Err(RsaError::InvalidKey);
        }
        let nonzero =
            |value: &PaddedBigUint| NonZero::new(value.clone()).ok_or(RsaError::InvalidKey);
        let modulus = nonzero(params.modulus())?;
        let e = params.public_exponent();
        self.key = Some(CrtKey {
            modulus_less_one: &*modulus - 1u32,
            public_exponent: with_width(e, e.bits().div_ceil(tc_bigint::Word::BITS) as usize),
            params_n: PaddedMontyParams::new(
                Odd::new((*modulus).clone()).ok_or(RsaError::InvalidKey)?,
            ),
            p: nonzero(params.p())?,
            q: nonzero(params.q())?,
            dp: params.dp().clone(),
            dq: params.dq().clone(),
            q_inv: params.q_inv().clone(),
            bits: modulus.bits(),
            direction,
            modulus,
        });
        Ok(())
    }
}

/// Reads the input as a big-endian integer `x` with `1 < x < n - 1`, as
/// Bouncy Castle does, and computes `m = x^d mod n` through the CRT:
/// `mP = (x mod p)^dP mod p` and `mQ = (x mod q)^dQ mod q`, each at the
/// width of its prime, `h = (mP - mQ) · qInv mod p`, and `m = h · q + mQ`.
/// It then checks that `m^e mod n` is `x` again, and fails with
/// `FaultyDecryptionOrSigning` otherwise, writing nothing; the result is
/// written over the full length of the modulus. Constant time, as the
/// arithmetic of `PaddedBigUint` and `tc_modular` is, apart from the
/// outcome of the range check and of the check of the result, which the
/// error shows. There is no blinding: a caller who needs it blinds the
/// input, as Bouncy Castle's `RsaBlindedEngine` does.
impl AsymmetricBlockCipher for PaddedRsaCrtCoreEngine {
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
        let (key, x, length) = self.read(input, output.len())?;
        let m = crt(key, &x)?;
        write_be(&*m, &mut output[..length]);
        Ok(length)
    }
}

/// Blinds the block with an `r` drawn uniformly from `[1, n)`, as Bouncy
/// Castle's `RsaBlindedEngine` does: `x · r^e mod n` goes through the CRT,
/// checked as without blinding, and the result is multiplied by
/// `r⁻¹ mod n`. Constant time in the secret values, `r` among them, as the
/// operation without blinding is; `r^e` raises to the public `e` from its
/// top bit only. An `r` that shares a factor with `n`, which only a
/// factoring of `n` would give, fails with `FaultyDecryptionOrSigning`.
impl RsaBlinding for PaddedRsaCrtCoreEngine {
    fn process_block_blinded<R: CryptoRng + ?Sized>(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        rng: &mut R,
    ) -> Result<usize, RsaError> {
        let (key, x, length) = self.read(input, output.len())?;
        let params = &key.params_n;
        let one = PaddedBigUint::from(1u8);
        let r = Zeroizing::new(PaddedBigUint::random_range(rng, &one, &key.modulus));
        let r = Zeroizing::new(PaddedMontyForm::new(&r, params));
        let unblind = Zeroizing::new(r.invert().ok_or(RsaError::FaultyDecryptionOrSigning)?);
        let blind = Zeroizing::new(r.pow_vartime(&key.public_exponent));
        let x = Zeroizing::new(PaddedMontyForm::new(&x, params));
        let blinded = Zeroizing::new((&*x * &*blind).retrieve());
        let m = crt(key, &blinded)?;
        let m = Zeroizing::new(PaddedMontyForm::new(&m, params));
        let m = Zeroizing::new((&*m * &*unblind).retrieve());
        write_be(&*m, &mut output[..length]);
        Ok(length)
    }
}

impl PaddedRsaCrtCoreEngine {
    /// The key, the input as a big-endian integer `x` with `1 < x < n - 1`,
    /// as Bouncy Castle asks, and the length of the output, once the
    /// engine is initialized and the blocks fit. Constant time, apart from
    /// the outcome of the checks, which the error shows.
    fn read(
        &self,
        input: &[u8],
        output: usize,
    ) -> Result<(&CrtKey, Zeroizing<PaddedBigUint>, usize), RsaError> {
        let key = self.key()?;
        if input.len() > self.input_block_size() {
            return Err(RsaError::InputTooLarge);
        }
        let length = self.output_block_size();
        if output < length {
            return Err(RsaError::OutputTooShort);
        }
        let Ok(x) = PaddedBigUint::from_be(input);
        let x = Zeroizing::new(x);
        if x.bits() <= 1 {
            return Err(RsaError::InputTooSmall);
        }
        if *x >= key.modulus_less_one {
            return Err(RsaError::InputTooLarge);
        }
        Ok((key, x, length))
    }
}

/// `x^d mod n` through the CRT, checked by raising it back to `e`: fails
/// with `FaultyDecryptionOrSigning` when it does not give `x` again.
/// Constant time, as the arithmetic of `PaddedBigUint` and `tc_modular` is.
fn crt(key: &CrtKey, x: &PaddedBigUint) -> Result<Zeroizing<PaddedBigUint>, RsaError> {
    let m_p = Zeroizing::new(power_mod_prime(x, &key.dp, &key.p));
    let m_q = Zeroizing::new(power_mod_prime(x, &key.dq, &key.q));
    let difference = Zeroizing::new(m_p.mod_sub(&m_q, &key.p));
    let h = Zeroizing::new(difference.mod_mul(&key.q_inv, &key.p));
    let mut m = Zeroizing::new(with_width(&h, key.modulus.as_limbs().len()));
    *m *= &*key.q;
    *m += &*m_q;

    if m.mod_pow(&key.public_exponent, &key.modulus) != *x {
        return Err(RsaError::FaultyDecryptionOrSigning);
    }
    Ok(m)
}

/// `(x mod prime)^exponent mod prime`, with the residue cut to the width of
/// the prime, so that the power runs at that width and not at the wider
/// one of `x`. Constant time: the widths are public.
fn power_mod_prime(
    x: &PaddedBigUint,
    exponent: &PaddedBigUint,
    prime: &NonZero<PaddedBigUint>,
) -> PaddedBigUint {
    let residue = Zeroizing::new(with_width(&(x % &**prime), prime.as_limbs().len()));
    residue.mod_pow(exponent, prime)
}

/// `value` at `width` limbs: zero limbs added, or the limbs past that
/// width, which must be zero, taken off. Constant time: the widths are
/// public.
fn with_width(value: &PaddedBigUint, width: usize) -> PaddedBigUint {
    let limbs = value.as_limbs();
    let kept = width.min(limbs.len());
    let mut resized = vec![Limb::new(0); width.max(1)];
    resized[..kept].copy_from_slice(&limbs[..kept]);
    PaddedBigUint::new(resized.into_boxed_slice())
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use tc_asym_cipher::{
        AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection, KeyPairGenerator,
        KeyPairGeneratorInit,
    };
    use tc_bigint::{ArrayEncoding, PaddedBigUint};

    use super::PaddedRsaCrtCoreEngine;
    use crate::testing::{D, DP, DQ, N, P, Q, Q_INV};
    use crate::{
        PaddedRsaCoreEngine, RsaError, RsaKeyGenerationParamsOwned, RsaKeyOwned,
        RsaKeyPairGenerator, RsaKeyParams, RsaPrivateCrtKeyOwned, RsaPrivateCrtKeyParams,
    };

    fn int(text: &str) -> PaddedBigUint {
        let bytes: alloc::vec::Vec<u8> = text
            .as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        PaddedBigUint::from_be(&bytes).unwrap()
    }

    fn wycheproof(dp: PaddedBigUint) -> RsaPrivateCrtKeyOwned<PaddedBigUint> {
        RsaPrivateCrtKeyOwned::new(
            int(N),
            PaddedBigUint::from(65537u32),
            int(D),
            int(P),
            int(Q),
            dp,
            int(DQ),
            int(Q_INV),
        )
    }

    /// The output of `engine` on `input`, at the 256 bytes of a 2048-bit
    /// modulus.
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
        let key = wycheproof(int(DP));
        let mut crt = PaddedRsaCrtCoreEngine::new();
        crt.init(CipherDirection::Decrypt, &key).unwrap();
        let plain_key = RsaKeyOwned::new(true, key.modulus().clone(), key.exponent().clone());
        let mut plain = PaddedRsaCoreEngine::new();
        plain.init(CipherDirection::Decrypt, &plain_key).unwrap();
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
        let key = wycheproof(int(DP));
        let public = RsaKeyOwned::new(false, key.modulus().clone(), key.public_exponent().clone());
        let mut encrypt = PaddedRsaCoreEngine::new();
        encrypt.init(CipherDirection::Encrypt, &public).unwrap();
        let mut message = [0x42; 255];
        message[0] = 0x01;
        let ciphertext = process(&mut encrypt, &message).unwrap();

        let mut decrypt = PaddedRsaCrtCoreEngine::new();
        decrypt.init(CipherDirection::Decrypt, &key).unwrap();
        let plaintext = process(&mut decrypt, &ciphertext).unwrap();
        assert_eq!(plaintext[0], 0);
        assert_eq!(&plaintext[1..], &message[..]);
    }

    #[test]
    fn a_wrong_crt_value_is_caught_by_the_check_of_the_result() {
        let key = wycheproof(int(DP) + 2u32);
        let mut engine = PaddedRsaCrtCoreEngine::new();
        engine.init(CipherDirection::Decrypt, &key).unwrap();
        let mut output = [0; 256];
        assert_eq!(
            engine.process_block(&[0x5a; 255], &mut output),
            Err(RsaError::FaultyDecryptionOrSigning)
        );
        assert_eq!(output, [0; 256]);
    }

    #[test]
    fn a_generated_key_signs_and_its_public_key_verifies() {
        let mut generator = RsaKeyPairGenerator::<PaddedBigUint>::new();
        generator
            .init(RsaKeyGenerationParamsOwned::new(StdRng::seed_from_u64(1)).with_strength(1024))
            .unwrap();
        let (public, private) = generator.generate_key_pair().unwrap();

        let mut sign = PaddedRsaCrtCoreEngine::new();
        sign.init(CipherDirection::Encrypt, &private).unwrap();
        assert_eq!(
            (sign.input_block_size(), sign.output_block_size()),
            (127, 128)
        );
        let message = [0x37; 127];
        let mut signature = [0; 128];
        sign.process_block(&message, &mut signature).unwrap();

        let mut verify = PaddedRsaCoreEngine::new();
        verify.init(CipherDirection::Decrypt, &public).unwrap();
        let mut recovered = [0; 128];
        verify.process_block(&signature, &mut recovered).unwrap();
        assert_eq!(recovered[0], 0);
        assert_eq!(&recovered[1..], &message[..]);
    }

    #[test]
    fn inputs_outside_two_to_n_less_two_are_turned_down() {
        let key = wycheproof(int(DP));
        let mut engine = PaddedRsaCrtCoreEngine::new();
        engine.init(CipherDirection::Decrypt, &key).unwrap();
        let mut output = [0; 256];
        assert_eq!(
            engine.process_block(&[1], &mut output),
            Err(RsaError::InputTooSmall)
        );
        let n = int(N).to_be();
        assert_eq!(
            engine.process_block(&n, &mut output),
            Err(RsaError::InputTooLarge)
        );
        assert_eq!(
            engine.process_block(&[2], &mut [0; 255]),
            Err(RsaError::OutputTooShort)
        );
    }

    #[test]
    fn a_key_that_fails_its_checks_is_turned_down() {
        let mut engine = PaddedRsaCrtCoreEngine::new();
        let key = wycheproof(PaddedBigUint::from(0u8));
        assert!(!key.validate());
        assert_eq!(
            engine.init(CipherDirection::Decrypt, &key),
            Err(RsaError::InvalidKey)
        );
    }

    #[test]
    fn a_blinded_block_comes_out_as_the_unblinded_one() {
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let key = wycheproof(int(DP));
        let mut plain = PaddedRsaCrtCoreEngine::new();
        plain.init(CipherDirection::Decrypt, &key).unwrap();
        let expected = process(&mut plain, &[0x5a; 255]);
        let mut blinded =
            crate::RsaBlindedEngine::<PaddedRsaCrtCoreEngine, _>::new(StdRng::seed_from_u64(2));
        blinded.init(CipherDirection::Decrypt, &key).unwrap();
        assert_eq!(process(&mut blinded, &[0x5a; 255]), expected);
        assert_eq!(process(&mut blinded, &[0x5a; 255]), expected);
    }

    #[test]
    fn an_engine_not_yet_initialized_processes_nothing() {
        let mut engine = PaddedRsaCrtCoreEngine::new();
        assert_eq!(
            (engine.input_block_size(), engine.output_block_size()),
            (0, 0)
        );
        assert_eq!(
            engine.process_block(&[2], &mut [0; 2]),
            Err(RsaError::NotInitialized)
        );
    }
}
