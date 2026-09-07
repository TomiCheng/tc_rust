//! SP 800-90A Hash_DRBG。

use alloc::{vec, vec::Vec};
use core::convert::Infallible;

use rand_core::{CryptoRng, TryCryptoRng, TryRng};
use tc_digest::Digest;

use crate::derivation::{hash_df, hash_seed_length, max_hash_security_strength};
use crate::drbg::{RngResult, rng_fill, rng_next_u32, rng_next_u64, validate_security_strength};
use crate::{Drbg, DrbgError};

const RESEED_MAX: u64 = 1_u64 << 47;
const MAX_REQUEST_BYTES: usize = (1_usize << 18) / 8;

/// NIST SP 800-90A §10.1.1 的 Hash_DRBG。
pub struct HashDrbg<D: Digest> {
    digest: D,
    value: Vec<u8>,
    constant: Vec<u8>,
    entropy_size: usize,
    seed_length: usize,
    reseed_counter: u64,
}

impl<D: Digest> HashDrbg<D> {
    /// 從呼叫端 RNG 取得熵並建立 Hash_DRBG。
    ///
    /// `security_strength` 使用 bits，`entropy_size` 是每次從 RNG 讀取的 bytes。
    pub fn new<R: CryptoRng + ?Sized>(
        mut digest: D,
        security_strength: usize,
        entropy_size: usize,
        rng: &mut R,
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<Self, DrbgError> {
        let output_size = digest.digest_size();
        let maximum = max_hash_security_strength(output_size)?;
        validate_security_strength(security_strength, maximum, entropy_size)?;
        let seed_length = hash_seed_length(output_size);

        let mut entropy = vec![0_u8; entropy_size];
        rng.fill_bytes(&mut entropy);
        let mut seed_material =
            Vec::with_capacity(entropy.len() + nonce.len() + personalization.len());
        seed_material.extend_from_slice(&entropy);
        seed_material.extend_from_slice(nonce);
        seed_material.extend_from_slice(personalization);

        let value = hash_df(&mut digest, &seed_material, seed_length)?;
        let mut constant_input = Vec::with_capacity(value.len() + 1);
        constant_input.push(0x00);
        constant_input.extend_from_slice(&value);
        let constant = hash_df(&mut digest, &constant_input, seed_length)?;

        Ok(Self {
            digest,
            value,
            constant,
            entropy_size,
            seed_length,
            reseed_counter: 1,
        })
    }

    fn hash(&mut self, parts: &[&[u8]]) -> Vec<u8> {
        for part in parts {
            self.digest.update(part);
        }
        let mut output = vec![0_u8; self.digest.digest_size()];
        let written = self.digest.do_final(&mut output);
        debug_assert_eq!(written, output.len());
        output
    }

    fn hashgen(&mut self, output: &mut [u8]) {
        let mut data = self.value.clone();
        let mut offset = 0;
        while offset < output.len() {
            let digest = self.hash(&[&data]);
            let take = core::cmp::min(digest.len(), output.len() - offset);
            output[offset..offset + take].copy_from_slice(&digest[..take]);
            offset += take;
            add_to(&mut data, &[1]);
        }
    }

    fn reseed_inner<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        additional_input: &[u8],
    ) -> Result<(), DrbgError> {
        let mut entropy = vec![0_u8; self.entropy_size];
        rng.fill_bytes(&mut entropy);
        let mut seed_material =
            Vec::with_capacity(1 + self.value.len() + entropy.len() + additional_input.len());
        seed_material.push(0x01);
        seed_material.extend_from_slice(&self.value);
        seed_material.extend_from_slice(&entropy);
        seed_material.extend_from_slice(additional_input);
        self.value = hash_df(&mut self.digest, &seed_material, self.seed_length)?;

        let mut constant_input = Vec::with_capacity(1 + self.value.len());
        constant_input.push(0x00);
        constant_input.extend_from_slice(&self.value);
        self.constant = hash_df(&mut self.digest, &constant_input, self.seed_length)?;
        self.reseed_counter = 1;
        Ok(())
    }
}

impl<D: Digest> Drbg for HashDrbg<D> {
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

        if !additional_input.is_empty() {
            let prefix = [0x02];
            let value = self.value.clone();
            let hash = self.hash(&[&prefix, &value, additional_input]);
            add_to(&mut self.value, &hash);
        }

        self.hashgen(output);

        let prefix = [0x03];
        let value = self.value.clone();
        let hash = self.hash(&[&prefix, &value]);
        add_to(&mut self.value, &hash);
        add_to(&mut self.value, &self.constant);
        add_to(&mut self.value, &(self.reseed_counter as u32).to_be_bytes());
        self.reseed_counter += 1;
        Ok(())
    }

    fn reseed<R: CryptoRng + ?Sized>(&mut self, rng: &mut R, additional_input: &[u8]) {
        self.reseed_inner(rng, additional_input)
            .expect("Hash_DRBG reseed 的 derivation function 必須可用");
    }
}

impl<D: Digest> TryRng for HashDrbg<D> {
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

impl<D: Digest> TryCryptoRng for HashDrbg<D> {}

fn add_to(longer: &mut [u8], shorter: &[u8]) {
    debug_assert!(longer.len() >= shorter.len());
    let offset = longer.len() - shorter.len();
    let mut carry = 0_u16;

    for index in (0..shorter.len()).rev() {
        carry += u16::from(longer[offset + index]) + u16::from(shorter[index]);
        longer[offset + index] = carry as u8;
        carry >>= 8;
    }
    for byte in longer[..offset].iter_mut().rev() {
        carry += u16::from(*byte);
        *byte = carry as u8;
        carry >>= 8;
    }
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    use rand_core::{TryCryptoRng, TryRng};
    use tc_sha::Sha256Digest;

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
        let mut drbg =
            HashDrbg::new(Sha256Digest::new(), 256, 32, &mut ZeroRng, &[0_u8; 16], &[]).unwrap();
        drbg.reseed_counter = RESEED_MAX + 1;

        assert_eq!(
            drbg.generate(&mut [0_u8; 1], &[]),
            Err(DrbgError::ReseedRequired)
        );
    }
}
