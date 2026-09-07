//! SP 800-90A AES CTR_DRBG。

use alloc::{vec, vec::Vec};
use core::convert::Infallible;

use rand_core::{CryptoRng, TryCryptoRng, TryRng};
use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_params::KeyRef;

use crate::derivation::block_cipher_df;
use crate::drbg::{RngResult, rng_fill, rng_next_u32, rng_next_u64, validate_security_strength};
use crate::{Drbg, DrbgError};

const AES_BLOCK_SIZE: usize = 16;
const RESEED_MAX: u64 = 1_u64 << 47;
const MAX_REQUEST_BYTES: usize = (1_usize << 18) / 8;

/// NIST SP 800-90A §10.2.1 的 AES CTR_DRBG。
pub struct CtrDrbg<C>
where
    C: BlockCipher + for<'a> BlockCipherInit<KeyRef<'a>>,
{
    cipher: C,
    key: Vec<u8>,
    value: Vec<u8>,
    key_size: usize,
    seed_length: usize,
    entropy_size: usize,
    use_derivation_function: bool,
    reseed_counter: u64,
}

impl<C> CtrDrbg<C>
where
    C: BlockCipher + for<'a> BlockCipherInit<KeyRef<'a>>,
{
    /// 使用 block cipher derivation function 建立 AES CTR_DRBG。
    pub fn new_with_derivation_function<R: CryptoRng + ?Sized>(
        cipher: C,
        key_size_bits: usize,
        security_strength: usize,
        entropy_size: usize,
        rng: &mut R,
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<Self, DrbgError> {
        Self::new(
            cipher,
            key_size_bits,
            security_strength,
            entropy_size,
            true,
            rng,
            nonce,
            personalization,
        )
    }

    /// 不使用 derivation function 建立 AES CTR_DRBG。
    ///
    /// `entropy_size + nonce.len() + personalization.len()` 必須正好等於 seedlen。
    pub fn new_without_derivation_function<R: CryptoRng + ?Sized>(
        cipher: C,
        key_size_bits: usize,
        security_strength: usize,
        entropy_size: usize,
        rng: &mut R,
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<Self, DrbgError> {
        Self::new(
            cipher,
            key_size_bits,
            security_strength,
            entropy_size,
            false,
            rng,
            nonce,
            personalization,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new<R: CryptoRng + ?Sized>(
        cipher: C,
        key_size_bits: usize,
        security_strength: usize,
        entropy_size: usize,
        use_derivation_function: bool,
        rng: &mut R,
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<Self, DrbgError> {
        let key_size = match key_size_bits {
            128 | 192 | 256 => key_size_bits / 8,
            _ => return Err(DrbgError::InvalidKeySize(key_size_bits)),
        };
        let block_size = cipher.block_size();
        if block_size != AES_BLOCK_SIZE {
            return Err(DrbgError::InvalidBlockSize(block_size));
        }
        validate_security_strength(security_strength, key_size_bits, entropy_size)?;
        let seed_length = key_size + block_size;

        let mut entropy = vec![0_u8; entropy_size];
        rng.fill_bytes(&mut entropy);
        let mut seed_material =
            Vec::with_capacity(entropy.len() + nonce.len() + personalization.len());
        seed_material.extend_from_slice(&entropy);
        seed_material.extend_from_slice(nonce);
        seed_material.extend_from_slice(personalization);

        let mut drbg = Self {
            cipher,
            key: vec![0_u8; key_size],
            value: vec![0_u8; block_size],
            key_size,
            seed_length,
            entropy_size,
            use_derivation_function,
            reseed_counter: 1,
        };
        let seed = drbg.prepare_seed(&seed_material)?;
        drbg.update(&seed)?;
        Ok(drbg)
    }

    fn prepare_seed(&mut self, input: &[u8]) -> Result<Vec<u8>, DrbgError> {
        if self.use_derivation_function {
            block_cipher_df(&mut self.cipher, self.key_size, input, self.seed_length)
        } else if input.len() == self.seed_length {
            Ok(input.to_vec())
        } else {
            Err(DrbgError::InvalidSeedLength {
                expected: self.seed_length,
                actual: input.len(),
            })
        }
    }

    fn update(&mut self, provided_data: &[u8]) -> Result<(), DrbgError> {
        debug_assert_eq!(provided_data.len(), self.seed_length);
        self.cipher
            .init(CipherDirection::Encrypt, &KeyRef::new(&self.key))
            .map_err(|_| DrbgError::CipherFailure)?;

        let mut temp = vec![0_u8; self.seed_length];
        for chunk in temp.chunks_mut(AES_BLOCK_SIZE) {
            increment(&mut self.value);
            let mut block = [0_u8; AES_BLOCK_SIZE];
            let written = self
                .cipher
                .process_block(&self.value, &mut block)
                .map_err(|_| DrbgError::CipherFailure)?;
            if written != AES_BLOCK_SIZE {
                return Err(DrbgError::CipherFailure);
            }
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        for (target, seed) in temp.iter_mut().zip(provided_data) {
            *target ^= *seed;
        }
        self.key.copy_from_slice(&temp[..self.key_size]);
        self.value.copy_from_slice(&temp[self.key_size..]);
        Ok(())
    }

    fn reseed_inner<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        additional_input: &[u8],
    ) -> Result<(), DrbgError> {
        let mut input = vec![0_u8; self.entropy_size];
        rng.fill_bytes(&mut input);
        input.extend_from_slice(additional_input);
        let seed = self.prepare_seed(&input)?;
        self.update(&seed)?;
        self.reseed_counter = 1;
        Ok(())
    }
}

impl<C> Drbg for CtrDrbg<C>
where
    C: BlockCipher + for<'a> BlockCipherInit<KeyRef<'a>>,
{
    fn generate(&mut self, output: &mut [u8], additional_input: &[u8]) -> Result<(), DrbgError> {
        if output.len() > MAX_REQUEST_BYTES {
            return Err(DrbgError::RequestTooLarge {
                requested: output.len(),
                maximum: MAX_REQUEST_BYTES,
            });
        }
        if self.reseed_counter > RESEED_MAX {
            return Err(DrbgError::ReseedRequired);
        }

        let seed = if additional_input.is_empty() {
            vec![0_u8; self.seed_length]
        } else {
            let seed = self.prepare_seed(additional_input)?;
            self.update(&seed)?;
            seed
        };

        self.cipher
            .init(CipherDirection::Encrypt, &KeyRef::new(&self.key))
            .map_err(|_| DrbgError::CipherFailure)?;
        for chunk in output.chunks_mut(AES_BLOCK_SIZE) {
            increment(&mut self.value);
            let mut block = [0_u8; AES_BLOCK_SIZE];
            let written = self
                .cipher
                .process_block(&self.value, &mut block)
                .map_err(|_| DrbgError::CipherFailure)?;
            if written != AES_BLOCK_SIZE {
                return Err(DrbgError::CipherFailure);
            }
            chunk.copy_from_slice(&block[..chunk.len()]);
        }

        self.update(&seed)?;
        self.reseed_counter += 1;
        Ok(())
    }

    fn reseed<R: CryptoRng + ?Sized>(&mut self, rng: &mut R, additional_input: &[u8]) {
        self.reseed_inner(rng, additional_input)
            .expect("CTR_DRBG reseed 的種子與底層 AES 必須有效");
    }
}

impl<C> TryRng for CtrDrbg<C>
where
    C: BlockCipher + for<'a> BlockCipherInit<KeyRef<'a>>,
{
    type Error = Infallible;

    fn try_next_u32(&mut self) -> RngResult<u32> {
        Ok(rng_next_u32(self))
    }

    fn try_next_u64(&mut self) -> RngResult<u64> {
        Ok(rng_next_u64(self))
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> RngResult<()> {
        rng_fill(self, output);
        Ok(())
    }
}

impl<C> TryCryptoRng for CtrDrbg<C> where C: BlockCipher + for<'a> BlockCipherInit<KeyRef<'a>> {}

fn increment(value: &mut [u8]) {
    let mut carry = 1_u16;
    for byte in value.iter_mut().rev() {
        carry += u16::from(*byte);
        *byte = carry as u8;
        carry >>= 8;
    }
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    use rand_core::{TryCryptoRng, TryRng};
    use tc_aes::AesEngine;

    use super::*;

    struct ZeroRng;

    impl TryRng for ZeroRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(0)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(0)
        }

        fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
            output.fill(0);
            Ok(())
        }
    }

    impl TryCryptoRng for ZeroRng {}

    #[test]
    fn reseed_limit_is_reported() {
        let mut drbg = CtrDrbg::new_with_derivation_function(
            AesEngine::new(),
            128,
            128,
            16,
            &mut ZeroRng,
            &[0_u8; 8],
            &[],
        )
        .unwrap();
        drbg.reseed_counter = RESEED_MAX + 1;

        assert_eq!(
            drbg.generate(&mut [0_u8; 1], &[]),
            Err(DrbgError::ReseedRequired)
        );
    }
}
