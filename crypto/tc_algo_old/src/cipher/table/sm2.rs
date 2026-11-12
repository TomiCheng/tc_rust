use rand::rngs::SysRng;
use rand_core::UnwrapErr;
use tc_asym_cipher::AsymmetricBlockCipherInit;
use tc_buffered_cipher::{BufferedCipher, BufferedCipherInit, BufferedError, CipherDirection};
use tc_sm2::{Sm2Engine, Sm2Error, Sm2Mode};
use tc_zeroize::{Zeroize, Zeroizing};

use super::specs::{MessageModeSpec, MessageSpec};
use crate::cipher::dyn_cipher::{DynCipher, Mapped};
use crate::cipher::init_params::{InitParams, Sm2Key, Sm2p256v1};
use crate::params::{AnyEcPrivateKey, AnyEcPublicKey, AnyKeyParams, AnyPrivateKey, AnyPublicKey};

// The ciphertext grows with the message, so the engine takes the whole message at once: update
// keeps the input, which may be the plaintext, and finalize hands it over. The kept input is
// wiped once it is used, on reset and on drop
struct BufferedSm2 {
    engine: Sm2Engine<Sm2p256v1, UnwrapErr<SysRng>>,
    initialized: bool,
    buffer: Zeroizing<Vec<u8>>,
}

impl BufferedSm2 {
    fn new(mode: Sm2Mode) -> Self {
        Self {
            engine: Sm2Engine::new(mode, UnwrapErr(SysRng)),
            initialized: false,
            buffer: Zeroizing::new(Vec::new()),
        }
    }

    fn check(&self) -> Result<(), BufferedError<Sm2Error>> {
        if self.initialized {
            Ok(())
        } else {
            Err(BufferedError::NotInitialized)
        }
    }
}

// The public key encrypts and the private key decrypts; the engine refuses either the other way
impl BufferedCipherInit<Sm2Key> for BufferedSm2 {
    type Error = Sm2Error;

    fn init(&mut self, direction: CipherDirection, key: &Sm2Key) -> Result<(), Sm2Error> {
        self.initialized = false;
        self.buffer.zeroize();
        match key {
            Sm2Key::Public(key) => self.engine.init(direction.into(), &**key)?,
            Sm2Key::Private(key) => self.engine.init(direction.into(), &**key)?,
        }
        self.initialized = true;
        Ok(())
    }
}

impl BufferedCipher for BufferedSm2 {
    type Error = BufferedError<Sm2Error>;

    fn block_size(&self) -> usize {
        0
    }

    fn update_output_len(&self, _input_len: usize) -> Result<usize, Self::Error> {
        self.check()?;
        Ok(0)
    }

    // C1, C2 and C3 when encrypting, C2 alone when decrypting
    fn output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        self.check()?;
        let total = self
            .buffer
            .len()
            .checked_add(input_len)
            .ok_or(BufferedError::InputTooLong)?;
        Ok(self.engine.output_size(total))
    }

    fn process_bytes(&mut self, input: &[u8], _output: &mut [u8]) -> Result<usize, Self::Error> {
        self.check()?;
        self.buffer.extend_from_slice(input);
        Ok(0)
    }

    // Too short an output keeps the input for another try; otherwise the input is used up, and
    // the next message goes under the same key, with a new random k
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let required = self.output_len(0)?;
        if output.len() < required {
            return Err(BufferedError::OutputTooShort {
                required,
                available: output.len(),
            });
        }
        let result = self.engine.process_block(&self.buffer, output);
        self.buffer.zeroize();
        result.map_err(BufferedError::Cipher)
    }

    fn reset(&mut self) {
        self.buffer.zeroize();
    }
}

fn boxed(mode: Sm2Mode) -> Box<dyn DynCipher> {
    Box::new(Mapped::<_, Sm2Key>::new(BufferedSm2::new(mode)))
}

// On sm2p256v1 alone, the curve of the standard
fn key(key: &AnyKeyParams) -> Option<InitParams> {
    match key {
        AnyKeyParams::Public(AnyPublicKey::Ec(AnyEcPublicKey::Sm2p256v1(key))) => {
            Some(InitParams::Sm2(Sm2Key::Public(key.clone())))
        }
        AnyKeyParams::Private(AnyPrivateKey::Ec(AnyEcPrivateKey::Sm2p256v1(key))) => {
            Some(InitParams::Sm2(Sm2Key::Private(key.clone())))
        }
        _ => None,
    }
}

// SM3 hashes, as in Bouncy Castle's SM2Engine. C1C2C3, the order of the old draft, comes first,
// as it is Bouncy Castle's default; GM/T 0003-2012 settled on C1C3C2
pub(super) const SM2: MessageSpec = MessageSpec {
    names: &["SM2"],
    modes: &[
        MessageModeSpec {
            name: "C1C2C3",
            create: || boxed(Sm2Mode::C1C2C3),
        },
        MessageModeSpec {
            name: "C1C3C2",
            create: || boxed(Sm2Mode::C1C3C2),
        },
    ],
    key,
};
