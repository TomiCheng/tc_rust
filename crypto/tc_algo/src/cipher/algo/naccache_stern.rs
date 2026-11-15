use core::error::Error;

use tc_buffered_cipher::{BufferedAsymmetricBlockCipher, BufferedCipherInit};
use tc_naccache_stern::{
    NaccacheSternEngine, NaccacheSternError, NaccacheSternPrivateKey, NaccacheSternPublicKey,
};

use super::asym::{Asym, Keys, Kind, invalid_params, row};
use crate::cipher::{CipherDirection, CipherEntry};
use crate::{AlgoError, DefaultAlgoContext, ErrorKind, Params};

// The row of Naccache-Stern, to give to DefaultAlgoBuilder::reg_cipher. Bouncy Castle has the engine
// but no name for it in CipherUtilities, so the name is the engine's, with no OID. It takes no
// padding: a padding would undo what the scheme is for, that the product of two ciphertexts
// decrypts to the sum of their messages
pub(super) fn naccache_stern(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![row(
        "NACCACHESTERN",
        "NACCACHESTERN",
        &["NOPADDING", "RAW"],
        &[],
        context.rand(),
        |_| {
            Box::new(Asym::<_, NaccacheSternKeys>::new(
                BufferedAsymmetricBlockCipher::new(NaccacheSternEngine::new()),
            ))
        },
    )]
}

// A NaccacheSternPublicKey to encrypt or a NaccacheSternPrivateKey to decrypt; the engine refuses
// the other way round
struct NaccacheSternKeys;

impl<C, I, J> Keys<C> for NaccacheSternKeys
where
    C: BufferedCipherInit<NaccacheSternPublicKey, Error = I>
        + BufferedCipherInit<NaccacheSternPrivateKey, Error = J>,
    I: Error + Send + Sync + 'static,
    J: Error + Send + Sync + 'static,
{
    fn init(
        cipher: &mut C,
        direction: CipherDirection,
        params: &dyn Params,
    ) -> Result<(), AlgoError> {
        let params = params.as_any();
        if let Some(key) = params.downcast_ref::<NaccacheSternPublicKey>() {
            return cipher.init(direction, key).map_err(invalid_params);
        }
        let key = params
            .downcast_ref::<NaccacheSternPrivateKey>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        cipher.init(direction, key).map_err(invalid_params)
    }
}

impl Kind for NaccacheSternError {
    fn kind(&self) -> ErrorKind {
        match self {
            NaccacheSternError::NotInitialized => ErrorKind::NotInitialized,
            // A ciphertext whose residues are in no table
            NaccacheSternError::LookupFailed => ErrorKind::InvalidCiphertext,
            NaccacheSternError::InputTooLarge
            | NaccacheSternError::InvalidCiphertextLength
            | NaccacheSternError::OutputTooShort => ErrorKind::DataLength,
            _ => ErrorKind::InvalidParams,
        }
    }
}
