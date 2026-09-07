//! SP 800-90A HMAC_DRBG。

use alloc::{vec, vec::Vec};
use core::convert::Infallible;

use rand_core::{CryptoRng, TryCryptoRng, TryRng};
use tc_macs::{Mac, MacInit};
use tc_params::KeyRef;

use crate::derivation::max_hash_security_strength;
use crate::drbg::{RngResult, rng_fill, rng_next_u32, rng_next_u64, validate_security_strength};
use crate::{Drbg, DrbgError};

const RESEED_MAX: u64 = 1_u64 << 47;
const MAX_REQUEST_BYTES: usize = (1_usize << 18) / 8;

/// NIST SP 800-90A §10.1.2 的 HMAC_DRBG。
pub struct HmacDrbg<M>
where
    M: Mac + for<'a> MacInit<KeyRef<'a>>,
{
    mac: M,
    key: Vec<u8>,
    value: Vec<u8>,
    entropy_size: usize,
    reseed_counter: u64,
}

impl<M> HmacDrbg<M>
where
    M: Mac + for<'a> MacInit<KeyRef<'a>>,
{
    /// 從呼叫端 RNG 取得熵並建立 HMAC_DRBG。
    ///
    /// `security_strength` 使用 bits，`entropy_size` 是每次從 RNG 讀取的 bytes。
    pub fn new<R: CryptoRng + ?Sized>(
        mac: M,
        security_strength: usize,
        entropy_size: usize,
        rng: &mut R,
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<Self, DrbgError> {
        let output_size = mac.mac_size();
        let maximum = max_hash_security_strength(output_size)?;
        validate_security_strength(security_strength, maximum, entropy_size)?;

        let mut entropy = vec![0_u8; entropy_size];
        rng.fill_bytes(&mut entropy);
        let mut seed_material =
            Vec::with_capacity(entropy.len() + nonce.len() + personalization.len());
        seed_material.extend_from_slice(&entropy);
        seed_material.extend_from_slice(nonce);
        seed_material.extend_from_slice(personalization);

        let mut drbg = Self {
            mac,
            key: vec![0_u8; output_size],
            value: vec![1_u8; output_size],
            entropy_size,
            reseed_counter: 1,
        };
        drbg.update(&seed_material)?;
        Ok(drbg)
    }

    fn update(&mut self, provided_data: &[u8]) -> Result<(), DrbgError> {
        self.update_round(0x00, provided_data)?;
        if !provided_data.is_empty() {
            self.update_round(0x01, provided_data)?;
        }
        Ok(())
    }

    fn update_round(&mut self, marker: u8, provided_data: &[u8]) -> Result<(), DrbgError> {
        self.mac
            .init(&KeyRef::new(&self.key))
            .map_err(|_| DrbgError::MacFailure)?;
        self.mac
            .update(&self.value)
            .map_err(|_| DrbgError::MacFailure)?;
        self.mac
            .update(&[marker])
            .map_err(|_| DrbgError::MacFailure)?;
        if !provided_data.is_empty() {
            self.mac
                .update(provided_data)
                .map_err(|_| DrbgError::MacFailure)?;
        }
        let written = self
            .mac
            .do_final(&mut self.key)
            .map_err(|_| DrbgError::MacFailure)?;
        if written != self.key.len() {
            return Err(DrbgError::MacFailure);
        }

        self.mac
            .init(&KeyRef::new(&self.key))
            .map_err(|_| DrbgError::MacFailure)?;
        self.mac
            .update(&self.value)
            .map_err(|_| DrbgError::MacFailure)?;
        let written = self
            .mac
            .do_final(&mut self.value)
            .map_err(|_| DrbgError::MacFailure)?;
        if written != self.value.len() {
            return Err(DrbgError::MacFailure);
        }
        Ok(())
    }

    fn reseed_inner<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        additional_input: &[u8],
    ) -> Result<(), DrbgError> {
        let mut seed_material = vec![0_u8; self.entropy_size];
        rng.fill_bytes(&mut seed_material);
        seed_material.extend_from_slice(additional_input);
        self.update(&seed_material)?;
        self.reseed_counter = 1;
        Ok(())
    }
}

impl<M> Drbg for HmacDrbg<M>
where
    M: Mac + for<'a> MacInit<KeyRef<'a>>,
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

        if !additional_input.is_empty() {
            self.update(additional_input)?;
        }

        for chunk in output.chunks_mut(self.value.len()) {
            self.mac
                .init(&KeyRef::new(&self.key))
                .map_err(|_| DrbgError::MacFailure)?;
            self.mac
                .update(&self.value)
                .map_err(|_| DrbgError::MacFailure)?;
            let written = self
                .mac
                .do_final(&mut self.value)
                .map_err(|_| DrbgError::MacFailure)?;
            if written != self.value.len() {
                return Err(DrbgError::MacFailure);
            }
            chunk.copy_from_slice(&self.value[..chunk.len()]);
        }

        self.update(additional_input)?;
        self.reseed_counter += 1;
        Ok(())
    }

    fn reseed<R: CryptoRng + ?Sized>(&mut self, rng: &mut R, additional_input: &[u8]) {
        self.reseed_inner(rng, additional_input)
            .expect("HMAC_DRBG reseed 的底層 MAC 必須可用");
    }
}

impl<M> TryRng for HmacDrbg<M>
where
    M: Mac + for<'a> MacInit<KeyRef<'a>>,
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

impl<M> TryCryptoRng for HmacDrbg<M> where M: Mac + for<'a> MacInit<KeyRef<'a>> {}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    use rand_core::{Rng, TryCryptoRng, TryRng};
    use tc_hmac::HMac;
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

    fn drbg() -> HmacDrbg<HMac<Sha256Digest>> {
        HmacDrbg::new(
            HMac::new(Sha256Digest::new()),
            256,
            32,
            &mut ZeroRng,
            &[0_u8; 16],
            &[],
        )
        .unwrap()
    }

    #[test]
    fn reseed_limit_is_reported_by_generate() {
        let mut drbg = drbg();
        drbg.reseed_counter = RESEED_MAX + 1;

        assert_eq!(
            drbg.generate(&mut [0_u8; 1], &[]),
            Err(DrbgError::ReseedRequired)
        );
    }

    #[test]
    #[should_panic(expected = "Rng::fill_bytes requires a usable DRBG")]
    fn rng_fill_panics_when_reseed_is_required() {
        let mut drbg = drbg();
        drbg.reseed_counter = RESEED_MAX + 1;

        drbg.fill_bytes(&mut [0_u8; 1]);
    }
}
