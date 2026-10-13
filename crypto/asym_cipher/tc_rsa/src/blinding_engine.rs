//! Chaum's blinding and unblinding, for an RSA blind signature, as Bouncy
//! Castle's `RsaBlindingEngine`.

use tc_asym_cipher::{
    AsymmetricBlockCipher, AsymmetricBlockCipherInit, AsymmetricKeyParams, CipherDirection,
};
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_modular::{Odd, PaddedMontyForm, PaddedMontyParams};
use tc_zeroize::{Zeroize, Zeroizing};

use crate::block::{input_block_size, output_block_size, write_be};
use crate::{RsaBlindingParams, RsaError, RsaKeyParams};

/// What the engine keeps from its initialization: `n - 1` for the range
/// check of the input, the public exponent, the blinding factor, the
/// Montgomery parameters of the modulus, the size of the modulus in bits,
/// and the direction. The factor and the parameters are wiped on drop.
struct Key {
    modulus_less_one: PaddedBigUint,
    public_exponent: PaddedBigUint,
    factor: PaddedBigUint,
    params: PaddedMontyParams,
    bits: u32,
    direction: CipherDirection,
}

/// Wipes the blinding factor and the parameters. Constant time.
impl Drop for Key {
    fn drop(&mut self) {
        self.factor.zeroize();
        self.params.zeroize();
    }
}

/// Chaum's blinding and unblinding, as Bouncy Castle's `RsaBlindingEngine`
/// does after the Handbook of Applied Cryptography, page 475, for a party
/// to have another sign a message without seeing it. Encrypting blinds a
/// message `m` as `m · rᵉ mod n`, with the public key `(n, e)` of the
/// signer and the blinding factor `r`; the signer signs it with its
/// private key, as `(m · rᵉ)ᵈ = mᵈ · r`; decrypting unblinds that as
/// `mᵈ · r · r⁻¹ mod n`, the signature of `m`. It takes
/// [`RsaBlindingParams`], over `PaddedBigUint`, and takes `alloc`.
///
/// The output takes the full length of the modulus, `(bits + 7) / 8`
/// bytes, leading zeros kept, in both directions, as the other engines of
/// the crate do; Bouncy Castle trims the unblinded signature.
///
/// ```
/// use tc_asym_cipher::{
///     AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection, KeyPairGenerator,
///     KeyPairGeneratorInit,
/// };
/// use tc_rsa_v2::{
///     RsaBlindingEngine, RsaBlindingFactorGenerator, RsaBlindingParams, RsaEngine,
///     RsaKeyGenerationParamsOwned, RsaKeyGenerator,
/// };
///
/// // The signer's key pair.
/// let mut generator = RsaKeyGenerator::new();
/// generator.init(RsaKeyGenerationParamsOwned::new(rand::rng()))?;
/// let (public, private) = generator.generate_key_pair()?;
///
/// // 1. The requester draws a blinding factor for the signer's public key,
/// //    and blinds the block to have signed; a real one is padded first.
/// let mut factors = RsaBlindingFactorGenerator::new(rand::rng());
/// factors.init(&public)?;
/// let params = RsaBlindingParams::new(public.clone(), factors.generate_blinding_factor()?);
/// let mut blinding = RsaBlindingEngine::new();
/// blinding.init(CipherDirection::Encrypt, &params)?;
/// let mut blinded = [0; 256];
/// blinding.process_block(b"a block the signer never sees", &mut blinded)?;
///
/// // 2. The signer signs the blinded block with its private key.
/// let mut signer = RsaEngine::new();
/// signer.init(CipherDirection::Decrypt, &private)?;
/// let mut blind_signature = [0; 256];
/// signer.process_block(&blinded, &mut blind_signature)?;
///
/// // 3. The requester unblinds it: the signature of the block itself.
/// blinding.init(CipherDirection::Decrypt, &params)?;
/// let mut signature = [0; 256];
/// blinding.process_block(&blind_signature, &mut signature)?;
/// # Ok::<(), tc_rsa_v2::RsaError>(())
/// ```
pub struct RsaBlindingEngine {
    key: Option<Key>,
}

impl RsaBlindingEngine {
    /// An engine to be initialized before it processes. Constant time.
    pub const fn new() -> Self {
        Self { key: None }
    }

    /// The key, once the engine is initialized. Constant time.
    fn key(&self) -> Result<&Key, RsaError> {
        self.key.as_ref().ok_or(RsaError::NotInitialized)
    }
}

/// Through [`new`](RsaBlindingEngine::new). Constant time.
impl Default for RsaBlindingEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Writes [`ALGO_NAME`](crate::ALGO_NAME), as Bouncy Castle's
/// `AlgorithmName`, without inspecting key material. Constant time with
/// respect to the key; output timing depends on the formatter.
impl core::fmt::Display for RsaBlindingEngine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(crate::ALGO_NAME)
    }
}

/// Copies the public key and the blinding factor in, once the key passes
/// [`validate`](RsaKeyParams::validate); fails with `InvalidKey` for a
/// private key, as Bouncy Castle's `RsaBlindingParameters` does, or one
/// that does not pass, and with `InvalidBlindingFactor` for a factor
/// below 2 or without an inverse modulo `n`. A failed `init` leaves the
/// engine uninitialized. Constant time in the factor, apart from the
/// outcome of its checks, which the error shows; variable time in the
/// public key.
impl AsymmetricBlockCipherInit<RsaBlindingParams> for RsaBlindingEngine {
    type Error = RsaError;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &RsaBlindingParams,
    ) -> Result<(), RsaError> {
        self.key = None;
        let key = params.public_key();
        if key.is_private_key() || !key.validate() {
            return Err(RsaError::InvalidKey);
        }
        let modulus = key.modulus();
        let odd = Odd::new(modulus.clone()).ok_or(RsaError::InvalidKey)?;
        let monty = PaddedMontyParams::new(odd);
        let factor = params.blinding_factor();
        let invertible = Zeroizing::new(PaddedMontyForm::new(factor, &monty))
            .invert()
            .map(Zeroizing::new)
            .is_some();
        if factor.bits() <= 1 || !invertible {
            return Err(RsaError::InvalidBlindingFactor);
        }
        self.key = Some(Key {
            modulus_less_one: modulus - 1u32,
            public_exponent: key.exponent().clone(),
            factor: factor.clone(),
            params: monty,
            bits: modulus.bits(),
            direction,
        });
        Ok(())
    }
}

/// Reads the input as a big-endian integer `x` with `1 < x < n - 1`, as
/// the other engines of the crate do, and multiplies it by `rᵉ` when
/// blinding or by `r⁻¹` when unblinding, mod `n`, in Montgomery form.
/// Constant time in the input and the factor: `rᵉ` is raised from the top
/// bit of the public `e`, and `r⁻¹` comes from safegcd; the outcome of the
/// range check shows in the error.
impl AsymmetricBlockCipher for RsaBlindingEngine {
    type Error = RsaError;

    /// `(bits - 1) / 8` bytes when blinding, so that any input is below the
    /// modulus, and `(bits + 7) / 8` when unblinding; zero before
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

    /// Blinds or unblinds the block, as the impl tells. Constant time in
    /// the input and the factor, apart from the outcome of the range check.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, RsaError> {
        let key = self.key()?;
        if input.len() > self.input_block_size() {
            return Err(RsaError::InputTooLarge);
        }
        let length = self.output_block_size();
        if output.len() < length {
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
        let x = Zeroizing::new(PaddedMontyForm::new(&x, &key.params));
        let r = Zeroizing::new(PaddedMontyForm::new(&key.factor, &key.params));
        let by = Zeroizing::new(match key.direction {
            CipherDirection::Encrypt => r.pow_vartime(&key.public_exponent),
            CipherDirection::Decrypt => r.invert().ok_or(RsaError::InvalidBlindingFactor)?,
        });
        let result = Zeroizing::new((&*x * &*by).retrieve());
        write_be(&*result, &mut output[..length]);
        Ok(length)
    }
}

#[cfg(test)]
mod tests {
    use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
    use tc_bigint::PaddedBigUint;

    use super::RsaBlindingEngine;
    use crate::{RsaBlindingParams, RsaError, RsaKey, RsaKeyOwned};

    fn int(value: u32) -> PaddedBigUint {
        PaddedBigUint::from(value)
    }

    /// The textbook key, p = 61 and q = 53, marked as checked, as its
    /// modulus has small factors.
    fn textbook(private: bool) -> RsaKey {
        let exponent = if private { 2753 } else { 17 };
        RsaKey::from(RsaKeyOwned::new(private, int(3233), int(exponent)).into_validated())
    }

    fn run(
        engine: &mut RsaBlindingEngine,
        direction: CipherDirection,
        factor: u32,
        x: &[u8],
    ) -> u16 {
        let params = RsaBlindingParams::new(textbook(false), int(factor));
        engine.init(direction, &params).unwrap();
        let mut output = [0; 2];
        assert_eq!(engine.process_block(x, &mut output), Ok(2));
        u16::from_be_bytes(output)
    }

    /// 65 blinded by 7 is `65 · 7¹⁷ mod 3233 = 2034`; signed, `2034²⁷⁵³ mod
    /// 3233 = 883`; unblinded, `883 · 7⁻¹ mod 3233 = 588`, which is
    /// `65²⁷⁵³ mod 3233`, the signature of 65 itself, worked out apart, with
    /// Python's `pow`.
    #[test]
    fn the_textbook_key_blinds_65_by_7_and_unblinds_its_signature() {
        let mut engine = RsaBlindingEngine::new();
        assert_eq!(run(&mut engine, CipherDirection::Encrypt, 7, &[65]), 2034);
        assert_eq!(
            run(
                &mut engine,
                CipherDirection::Decrypt,
                7,
                &883u16.to_be_bytes()
            ),
            588
        );
    }

    #[test]
    fn a_blind_signature_unblinds_to_the_signature_of_the_message_itself() {
        use rand::SeedableRng;
        use rand::rngs::StdRng;
        use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};

        use crate::{
            RsaBlindingFactorGenerator, RsaEngine, RsaKeyGenerationParamsOwned, RsaKeyGenerator,
        };

        let mut generator = RsaKeyGenerator::new();
        let params = RsaKeyGenerationParamsOwned::new(StdRng::seed_from_u64(5)).with_strength(1024);
        generator.init(params).unwrap();
        let (public, private) = generator.generate_key_pair().unwrap();
        let mut factors = RsaBlindingFactorGenerator::new(StdRng::seed_from_u64(6));
        factors.init(&public).unwrap();
        let params = RsaBlindingParams::new(public, factors.generate_blinding_factor().unwrap());
        let message = [0x5a; 127];
        let process = |engine: &mut dyn AsymmetricBlockCipher<Error = RsaError>, input: &[u8]| {
            let mut output = [0; 128];
            assert_eq!(engine.process_block(input, &mut output), Ok(128));
            output
        };

        let mut blinding = RsaBlindingEngine::new();
        blinding.init(CipherDirection::Encrypt, &params).unwrap();
        let blinded = process(&mut blinding, &message);
        assert_ne!(&blinded[1..], &message[..]);
        let mut signer = RsaEngine::new();
        signer.init(CipherDirection::Decrypt, &private).unwrap();
        let blind_signature = process(&mut signer, &blinded);
        blinding.init(CipherDirection::Decrypt, &params).unwrap();
        let signature = process(&mut blinding, &blind_signature);

        assert_eq!(signature, process(&mut signer, &message));
    }

    #[test]
    fn a_private_key_or_a_factor_without_an_inverse_is_turned_down() {
        let mut engine = RsaBlindingEngine::new();
        let private = RsaBlindingParams::new(textbook(true), int(7));
        assert_eq!(
            engine.init(CipherDirection::Encrypt, &private),
            Err(RsaError::InvalidKey)
        );
        for factor in [0, 1, 61, 53, 3233] {
            let params = RsaBlindingParams::new(textbook(false), int(factor));
            assert_eq!(
                engine.init(CipherDirection::Encrypt, &params),
                Err(RsaError::InvalidBlindingFactor),
                "{factor}"
            );
        }
        assert_eq!(
            engine.process_block(&[2], &mut [0; 2]),
            Err(RsaError::NotInitialized)
        );
    }

    #[test]
    fn inputs_outside_two_to_n_less_two_are_turned_down() {
        let mut engine = RsaBlindingEngine::new();
        let params = RsaBlindingParams::new(textbook(false), int(7));
        engine.init(CipherDirection::Decrypt, &params).unwrap();
        assert_eq!(
            engine.process_block(&[1], &mut [0; 2]),
            Err(RsaError::InputTooSmall)
        );
        assert_eq!(
            engine.process_block(&3232u16.to_be_bytes(), &mut [0; 2]),
            Err(RsaError::InputTooLarge)
        );
        assert_eq!(
            engine.process_block(&[2], &mut [0; 1]),
            Err(RsaError::OutputTooShort)
        );
    }

    #[test]
    fn the_engine_is_named_rsa_and_sized_as_the_modulus() {
        extern crate alloc;
        use alloc::string::ToString;

        let mut engine = RsaBlindingEngine::new();
        assert_eq!(engine.to_string(), "RSA");
        assert_eq!(
            (engine.input_block_size(), engine.output_block_size()),
            (0, 0)
        );
        let params = RsaBlindingParams::new(textbook(false), int(7));
        engine.init(CipherDirection::Encrypt, &params).unwrap();
        assert_eq!(
            (engine.input_block_size(), engine.output_block_size()),
            (1, 2)
        );
    }
}
