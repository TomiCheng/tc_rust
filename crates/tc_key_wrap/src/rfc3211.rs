//! RFC 3211 key-wrap engine.

use alloc::string::String;
use alloc::vec;
use rand_core::CryptoRng;
use tc_block_modes::{CbcBlockCipher, CbcParams};
use tc_cipher_core::{
    BlockCipher, BlockCipherInit, CipherDirection, KeyWrap, KeyWrapInit, WrapDirection,
};

use crate::WrapError;

const ALGORITHM_SUFFIX: &str = "/RFC3211Wrap";

/// Parameters for RFC 3211: the underlying cipher's key parameters plus an IV.
///
/// The IV is copied into owned storage so the parameter type does not borrow it.
/// Its length is validated during initialization because only the engine knows
/// the underlying block size.
pub struct Rfc3211Params<P> {
    /// CBC parameters containing the underlying key parameters and copied IV.
    cbc_params: CbcParams<P>,
}

impl<P> Rfc3211Params<P> {
    /// Builds RFC 3211 parameters and copies the required IV.
    pub fn new(key_params: P, iv: &[u8]) -> Self {
        Self {
            cbc_params: CbcParams::with_iv(key_params, iv),
        }
    }
}

/// RFC 3211 key-wrap engine, generic over the underlying block cipher.
///
/// Wrapping uses CBC mode and caller-provided cryptographically secure
/// randomness. Unwrapping validates the embedded length and three complement
/// check bytes before releasing recovered key material to the caller.
pub struct Rfc3211WrapEngine<E: BlockCipher, R: CryptoRng> {
    /// CBC mode over the underlying block cipher.
    engine: CbcBlockCipher<E>,
    /// The caller-provided cryptographically secure RNG used for wrap padding.
    rng: R,
    /// The composed `<cipher>/RFC3211Wrap` algorithm name.
    name: String,
    /// The key-level operation selected during initialization.
    direction: Option<WrapDirection>,
}

impl<E: BlockCipher, R: CryptoRng> Rfc3211WrapEngine<E, R> {
    /// Builds an RFC 3211 wrapper over the given block cipher and RNG.
    pub fn new(engine: E, rng: R) -> Self {
        let base_name = engine.algorithm_name();
        let mut name = String::with_capacity(base_name.len() + ALGORITHM_SUFFIX.len());
        name.push_str(base_name);
        name.push_str(ALGORITHM_SUFFIX);

        Self {
            engine: CbcBlockCipher::new(engine),
            rng,
            name,
            direction: None,
        }
    }
}

impl<E: BlockCipher, R: CryptoRng> KeyWrap for Rfc3211WrapEngine<E, R> {
    type Error = WrapError<E>;

    fn algorithm_name(&self) -> &str {
        &self.name
    }

    fn wrapped_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        if input_len > u8::MAX as usize {
            return Err(WrapError::WrapDataLength);
        }

        let block_size = self.engine.block_size();
        if block_size < 4 {
            return Err(WrapError::UnsupportedBlockSize {
                actual: block_size,
                minimum: 4,
            });
        }

        let payload_len = input_len.checked_add(4).ok_or(WrapError::WrapDataLength)?;
        let minimum_len = block_size.checked_mul(2).ok_or(WrapError::WrapDataLength)?;
        let rounded_len = payload_len
            .div_ceil(block_size)
            .checked_mul(block_size)
            .ok_or(WrapError::WrapDataLength)?;

        Ok(core::cmp::max(minimum_len, rounded_len))
    }

    fn max_unwrapped_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        let block_size = self.engine.block_size();
        if block_size < 4 {
            return Err(WrapError::UnsupportedBlockSize {
                actual: block_size,
                minimum: 4,
            });
        }

        let minimum_len = block_size
            .checked_mul(2)
            .ok_or(WrapError::UnwrapDataLength)?;
        if input_len < minimum_len || !input_len.is_multiple_of(block_size) {
            return Err(WrapError::UnwrapDataLength);
        }

        Ok(input_len - 4)
    }

    fn wrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        match self.direction {
            Some(WrapDirection::Wrap) => {}
            Some(WrapDirection::Unwrap) => return Err(WrapError::NotForWrapping),
            None => return Err(WrapError::Uninitialised),
        }

        let required = self.wrapped_len(input.len())?;
        if output.len() < required {
            return Err(WrapError::OutputBufferTooShort {
                required,
                available: output.len(),
            });
        }

        self.engine.reset();
        let buffer = &mut output[..required];
        buffer[0] = input.len() as u8;
        buffer[4..4 + input.len()].copy_from_slice(input);
        self.rng.fill_bytes(&mut buffer[4 + input.len()..]);
        buffer[1] = !buffer[4];
        buffer[2] = !buffer[5];
        buffer[3] = !buffer[6];

        let block_size = self.engine.block_size();
        let mut input_block = vec![0_u8; block_size];
        for _ in 0..2 {
            for output_block in buffer.chunks_exact_mut(block_size) {
                input_block.copy_from_slice(output_block);
                self.engine
                    .process_block(&input_block, output_block)
                    .map_err(WrapError::BlockCipherMode)?;
            }
        }

        Ok(required)
    }

    fn unwrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        match self.direction {
            Some(WrapDirection::Unwrap) => {}
            Some(WrapDirection::Wrap) => return Err(WrapError::NotForUnwrapping),
            None => return Err(WrapError::Uninitialised),
        }

        let required = self.max_unwrapped_len(input.len())?;
        if output.len() < required {
            return Err(WrapError::OutputBufferTooShort {
                required,
                available: output.len(),
            });
        }

        let block_size = self.engine.block_size();
        let mut cek_block = input.to_vec();
        let mut iv = vec![0_u8; block_size];
        let mut input_block = vec![0_u8; block_size];
        iv.copy_from_slice(&input[..block_size]);

        // Undo the second CBC pass for every block except the first. Its first
        // ciphertext block is the IV needed to start at block two.
        self.engine
            .reset_with_iv(&iv)
            .map_err(WrapError::BlockCipherMode)?;
        for offset in (block_size..cek_block.len()).step_by(block_size) {
            input_block.copy_from_slice(&cek_block[offset..offset + block_size]);
            if let Err(error) = self
                .engine
                .process_block(&input_block, &mut cek_block[offset..offset + block_size])
            {
                cek_block.fill(0);
                input_block.fill(0);
                iv.fill(0);
                return Err(WrapError::BlockCipherMode(error));
            }
        }

        // The last recovered block above is the chaining value immediately
        // before the first block of the second pass.
        iv.copy_from_slice(&cek_block[cek_block.len() - block_size..]);
        self.engine
            .reset_with_iv(&iv)
            .map_err(WrapError::BlockCipherMode)?;
        input_block.copy_from_slice(&cek_block[..block_size]);
        if let Err(error) = self
            .engine
            .process_block(&input_block, &mut cek_block[..block_size])
        {
            cek_block.fill(0);
            input_block.fill(0);
            iv.fill(0);
            return Err(WrapError::BlockCipherMode(error));
        }

        // Undo the first CBC pass from the original IV selected at init.
        self.engine.reset();
        for offset in (0..cek_block.len()).step_by(block_size) {
            input_block.copy_from_slice(&cek_block[offset..offset + block_size]);
            if let Err(error) = self
                .engine
                .process_block(&input_block, &mut cek_block[offset..offset + block_size])
            {
                cek_block.fill(0);
                input_block.fill(0);
                iv.fill(0);
                return Err(WrapError::BlockCipherMode(error));
            }
        }

        let key_len = usize::from(cek_block[0]);
        let invalid_length = key_len > cek_block.len() - 4;
        let mut difference = 0_u8;
        for index in 0..3 {
            difference |= (!cek_block[1 + index]) ^ cek_block[4 + index];
        }

        if invalid_length || difference != 0 {
            cek_block.fill(0);
            input_block.fill(0);
            iv.fill(0);
            return Err(WrapError::IntegrityCheckFailed);
        }

        output[..key_len].copy_from_slice(&cek_block[4..4 + key_len]);
        cek_block.fill(0);
        input_block.fill(0);
        iv.fill(0);
        Ok(key_len)
    }
}

impl<E: BlockCipherInit, R: CryptoRng> KeyWrapInit for Rfc3211WrapEngine<E, R> {
    type Params<'a> = Rfc3211Params<E::Params<'a>>;

    fn init(
        &mut self,
        direction: WrapDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        let cipher_direction = match direction {
            WrapDirection::Wrap => CipherDirection::Encrypt,
            WrapDirection::Unwrap => CipherDirection::Decrypt,
        };
        self.engine
            .init(cipher_direction, &params.cbc_params)
            .map_err(WrapError::BlockCipherMode)?;
        self.direction = Some(direction);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    use rand_core::{TryCryptoRng, TryRng};
    use tc_block_cipher::AesEngine;
    use tc_cipher_core::KeyWrap;

    use super::Rfc3211WrapEngine;

    struct FixedCryptoRng;

    impl TryRng for FixedCryptoRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(0x5a5a_5a5a)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(0x5a5a_5a5a_5a5a_5a5a)
        }

        fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
            output.fill(0x5a);
            Ok(())
        }
    }

    impl TryCryptoRng for FixedCryptoRng {}

    #[test]
    fn algorithm_name_includes_the_underlying_cipher() {
        let wrapper = Rfc3211WrapEngine::new(AesEngine::new(), FixedCryptoRng);

        assert_eq!(wrapper.algorithm_name(), "AES/RFC3211Wrap");
    }
}
