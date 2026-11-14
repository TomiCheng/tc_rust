use core::error::Error;

use tc_aead_cipher::{AeadBlockCipher, AeadCipherInit, AeadError, AeadParamsOwned};

use super::buffered::{downcast, invalid_params};
use crate::cipher::{BufferedCipher, Cipher, CipherDirection};
use crate::{AlgoError, ErrorKind, Params};

// A block cipher in an AEAD mode of tc_aead_cipher, GCM, CCM, EAX or OCB, behind Cipher. Its params
// are an AeadParamsOwned. Encryption ends with the tag, and decryption expects it at the end of the
// input. As in Bouncy Castle, update may give plaintext before finalize has checked the tag, so a
// caller that uses update has to discard it when finalize fails
pub(super) struct Aead<C>(pub(super) C);

impl<C, E> BufferedCipher for Aead<C>
where
    C: AeadBlockCipher<Error = AeadError<E>>,
    E: Error + Send + Sync + 'static,
{
    type Error = AlgoError;

    fn block_size(&self) -> usize {
        self.0.block_size()
    }

    fn update_output_len(&self, input_len: usize) -> Result<usize, AlgoError> {
        self.0.update_output_len(input_len).map_err(aead_error)
    }

    fn output_len(&self, input_len: usize) -> Result<usize, AlgoError> {
        self.0.output_len(input_len).map_err(aead_error)
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, AlgoError> {
        self.0.process_bytes(input, output).map_err(aead_error)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        self.0.do_final(output).map_err(aead_error)
    }

    fn reset(&mut self) {
        self.0.reset();
    }
}

impl<C, E, I> Cipher for Aead<C>
where
    C: AeadBlockCipher<Error = AeadError<E>> + AeadCipherInit<AeadParamsOwned, Error = I>,
    E: Error + Send + Sync + 'static,
    I: Error + Send + Sync + 'static,
{
    fn init(&mut self, direction: CipherDirection, params: &dyn Params) -> Result<(), AlgoError> {
        let params = downcast::<AeadParamsOwned>(params)?;
        self.0
            .init(direction.into(), params)
            .map_err(invalid_params)
    }
}

pub(super) fn aead_error<E: Error + Send + Sync + 'static>(error: AeadError<E>) -> AlgoError {
    let kind = match error {
        // A finished encryption takes a new init, so that no nonce is used twice
        AeadError::NotInitialized | AeadError::AlreadyFinalized => ErrorKind::NotInitialized,
        // Too short to hold the tag is told apart no more than a wrong tag
        AeadError::AuthenticationFailed | AeadError::CiphertextTooShort { .. } => {
            ErrorKind::InvalidCiphertext
        }
        _ => ErrorKind::DataLength,
    };
    AlgoError::with_source(kind, error)
}
