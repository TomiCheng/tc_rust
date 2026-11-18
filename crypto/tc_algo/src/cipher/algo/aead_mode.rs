use core::error::Error;
use core::marker::PhantomData;

use tc_aead_cipher::{AeadBlockCipher, AeadCipherInit, AeadError, AeadParamsOwned};

#[cfg(any(feature = "rc-cipher", feature = "gost28147", feature = "threefish"))]
use super::buffered::Own;
use super::buffered::{NoOwn, downcast, invalid_params};
use crate::cipher::{BufferedCipher, Cipher, CipherDirection};
use crate::{AlgoError, ErrorKind, Params};

// A block cipher in an AEAD mode of tc_aead_cipher behind Cipher. Its params are an
// AeadParamsOwned and, with Own<O>, a ParamsWithAeadOwned<O> of the engine's own params, which the
// mode gives the engine alone. Encryption ends with the tag, and decryption expects it at the end of
// the input. As in Bouncy Castle, update may give plaintext before finalize has checked the tag, so
// a caller that uses update has to discard it when finalize fails
pub(super) struct Aead<C, O = NoOwn>(pub(super) C, pub(super) PhantomData<fn() -> O>);

// Inits the mode when params are the row's own params with the AEAD values, and gives None when
// they are not
pub(super) trait OwnAead<C> {
    fn init(
        cipher: &mut C,
        direction: CipherDirection,
        params: &dyn Params,
    ) -> Option<Result<(), AlgoError>>;
}

impl<C> OwnAead<C> for NoOwn {
    fn init(_: &mut C, _: CipherDirection, _: &dyn Params) -> Option<Result<(), AlgoError>> {
        None
    }
}

#[cfg(any(feature = "rc-cipher", feature = "gost28147", feature = "threefish"))]
impl<C, O: 'static> OwnAead<C> for Own<O>
where
    C: AeadCipherInit<crate::params::ParamsWithAeadOwned<O>>,
    <C as AeadCipherInit<crate::params::ParamsWithAeadOwned<O>>>::Error:
        Error + Send + Sync + 'static,
{
    fn init(
        cipher: &mut C,
        direction: CipherDirection,
        params: &dyn Params,
    ) -> Option<Result<(), AlgoError>> {
        let params = params
            .as_any()
            .downcast_ref::<crate::params::ParamsWithAeadOwned<O>>()?;
        Some(
            cipher
                .init(direction.into(), params)
                .map_err(invalid_params),
        )
    }
}

impl<C, O, E> BufferedCipher for Aead<C, O>
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

impl<C, O, E, I> Cipher for Aead<C, O>
where
    C: AeadBlockCipher<Error = AeadError<E>> + AeadCipherInit<AeadParamsOwned, Error = I>,
    E: Error + Send + Sync + 'static,
    I: Error + Send + Sync + 'static,
    O: OwnAead<C>,
{
    fn init(&mut self, direction: CipherDirection, params: &dyn Params) -> Result<(), AlgoError> {
        if let Some(result) = O::init(&mut self.0, direction, params) {
            return result;
        }
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
