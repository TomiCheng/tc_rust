use rand_core::CryptoRng;
use tc_sm2::{Sm2Engine, Sm2Error, Sm2Mode};
use tc_zeroize::Zeroizing;

use super::asym::row;
use crate::cipher::{BufferedCipher, Cipher, CipherDirection, CipherEntry};
use crate::params::key::sm2::{Sm2Curve, Sm2PrivateKey, Sm2PublicKey};
use crate::{AlgoError, DefaultAlgoContext, ErrorKind, Params};

// The rows of SM2 encryption, of GM/T 0003, over sm2p256v1 with SM3. Bouncy Castle has the engine
// but no name for it in CipherUtilities, so the names are this crate's: the order of the three
// parts of the ciphertext takes the place of the padding, and SM2 alone is C1C2C3, Bouncy Castle's
// default, where the standard of 2012 has C1C3C2
pub(super) fn sm2(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand = context.rand();
    vec![
        row("SM2", "SM2", &["C1C2C3"], &[], rand, |rand| {
            Box::new(Sm2::new(Sm2Mode::C1C2C3, rand()))
        }),
        row("SM2", "SM2//C1C3C2", &["C1C3C2"], &[], rand, |rand| {
            Box::new(Sm2::new(Sm2Mode::C1C3C2, rand()))
        }),
    ]
}

// SM2 behind Cipher. Its ciphertext is as long as the message and a point and a hash, not a block,
// so the message gathers until do_final encrypts or decrypts it whole, and nothing comes out
// before. Its params are an SM2 public key to encrypt and a private key to decrypt, as the SM2 row
// of the key pair generators gives them
struct Sm2 {
    engine: Sm2Engine<Sm2Curve, Box<dyn CryptoRng>>,
    input: Zeroizing<Vec<u8>>,
}

impl Sm2 {
    fn new(mode: Sm2Mode, rand: Box<dyn CryptoRng>) -> Self {
        Self {
            engine: Sm2Engine::new(mode, rand),
            input: Zeroizing::new(Vec::new()),
        }
    }
}

impl BufferedCipher for Sm2 {
    type Error = AlgoError;

    // Zero, as for a stream cipher: the ciphertext is not in blocks
    fn block_size(&self) -> usize {
        0
    }

    fn update_output_len(&self, _input_len: usize) -> Result<usize, AlgoError> {
        Ok(0)
    }

    fn output_len(&self, input_len: usize) -> Result<usize, AlgoError> {
        let total = self
            .input
            .len()
            .checked_add(input_len)
            .ok_or(AlgoError::new(ErrorKind::DataLength))?;
        Ok(self.engine.output_size(total))
    }

    fn process_bytes(&mut self, input: &[u8], _output: &mut [u8]) -> Result<usize, AlgoError> {
        self.input.extend_from_slice(input);
        Ok(0)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        let result = self.engine.process_block(&self.input, output);
        self.input.clear();
        result.map_err(sm2_error)
    }

    fn reset(&mut self) {
        self.input.clear();
    }
}

impl Cipher for Sm2 {
    fn init(&mut self, direction: CipherDirection, params: &dyn Params) -> Result<(), AlgoError> {
        use tc_asym_cipher::AsymmetricBlockCipherInit;

        self.input.clear();
        let params = params.as_any();
        let result = if let Some(key) = params.downcast_ref::<Sm2PublicKey>() {
            self.engine.init(direction.into(), key)
        } else if let Some(key) = params.downcast_ref::<Sm2PrivateKey>() {
            self.engine.init(direction.into(), key)
        } else {
            return Err(AlgoError::new(ErrorKind::InvalidParams));
        };
        result.map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))
    }
}

fn sm2_error(error: Sm2Error) -> AlgoError {
    let kind = match error {
        Sm2Error::NotInitialized => ErrorKind::NotInitialized,
        // A point off the curve, a wrong hash or a ciphertext too short to hold both are told
        // apart no more than a wrong tag
        Sm2Error::InvalidPoint | Sm2Error::InvalidCiphertext | Sm2Error::CiphertextTooShort => {
            ErrorKind::InvalidCiphertext
        }
        Sm2Error::EmptyInput | Sm2Error::OutputTooShort => ErrorKind::DataLength,
        _ => ErrorKind::InvalidParams,
    };
    AlgoError::with_source(kind, error)
}
