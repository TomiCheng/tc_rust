//! GMAC adapter over the shared GCM implementation.

use core::fmt;

use tc_cipher::{
    AeadBlockCipher, AeadBlockError, AeadBlockInitError, AeadCipher, BlockCipher, BlockCipherInit,
    CipherDirection,
};
use tc_crypto::AlgorithmName;
use tc_gcm::GcmBlockCipher;
use tc_macs::{Mac, MacInit};
use tc_params::{IvParams, KeyParams};

use crate::{CreateError, MAX_MAC_BYTES, MIN_MAC_BYTES};

/// The authentication-only specialization of GCM.
///
/// All message input is passed to GCM as associated data. Because nonce reuse
/// is unsafe, successful finalization leaves the instance finalized; call
/// [`MacInit::init`] with a fresh nonce before the next message.
pub struct GMac<C> {
    cipher: GcmBlockCipher<C>,
    mac_size: usize,
}

impl<C: BlockCipher> GMac<C> {
    /// Creates GMAC with a 16-byte authentication tag.
    pub fn new(cipher: C) -> Result<Self, CreateError> {
        Self::with_mac_size(cipher, MAX_MAC_BYTES)
    }

    /// Creates GMAC with a tag containing `mac_size` bytes.
    pub fn with_mac_size(cipher: C, mac_size: usize) -> Result<Self, CreateError> {
        let block_size = cipher.block_size();
        if block_size != MAX_MAC_BYTES {
            return Err(CreateError::InvalidBlockSize(block_size));
        }
        if !(MIN_MAC_BYTES..=MAX_MAC_BYTES).contains(&mac_size) {
            return Err(CreateError::InvalidMacSize(mac_size));
        }
        Ok(Self {
            cipher: GcmBlockCipher::new(cipher),
            mac_size,
        })
    }

    /// Returns the block cipher used by GCM.
    pub fn underlying_cipher(&self) -> &C {
        self.cipher.underlying_cipher()
    }
}

impl<C> AlgorithmName for GMac<C>
where
    C: BlockCipher + AlgorithmName,
{
    fn write_algo_name(&self, output: &mut dyn fmt::Write) -> fmt::Result {
        self.underlying_cipher().write_algo_name(output)?;
        output.write_str("-GMAC")
    }
}

impl<C: BlockCipher> Mac for GMac<C> {
    type Error = AeadBlockError<C::Error>;

    fn mac_size(&self) -> usize {
        self.mac_size
    }

    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.cipher.process_aad_bytes(input)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.cipher.do_final(output)
    }

    fn reset(&mut self) {
        self.cipher.reset();
    }
}

impl<C, P> MacInit<P> for GMac<C>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: KeyParams + IvParams + ?Sized,
{
    type Error = AeadBlockInitError<<C as BlockCipherInit<P>>::Error>;

    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.cipher.init_with_parts(
            CipherDirection::Encrypt,
            params,
            params.iv(),
            &[],
            self.mac_size,
        )
    }
}
