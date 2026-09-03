//! ChaCha20-Poly1305 authenticated-encryption engine.

use core::fmt;

use tc_chacha::{ChaCha7539Engine, XChaCha20Engine};
use tc_cipher::{
    AeadCipher, AeadCipherInit, AeadError, CipherDirection, InitError, StreamCipher,
    StreamCipherInit, StreamError,
};
use tc_crypto::AlgorithmName;
use tc_macs::{Mac, MacError, MacInit};
use tc_params::{InitialAadParams, IvParams, KeyParams};
use tc_poly1305::Engine as Poly1305;

use crate::{KEY_BYTES, NONCE_BYTES, TAG_BYTES, XNONCE_BYTES};

const BLOCK_BYTES: usize = 64;
const MAC_BLOCK_BYTES: usize = 16;
const DECRYPT_BUFFER_BYTES: usize = BLOCK_BYTES + TAG_BYTES;
const DATA_LIMIT: u64 = (u32::MAX as u64) * BLOCK_BYTES as u64;
const MAX_NONCE_BYTES: usize = 24;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum State {
    #[default]
    Uninitialised,
    EncryptInit,
    EncryptAad,
    EncryptData,
    EncryptFinal,
    DecryptInit,
    DecryptAad,
    DecryptData,
    DecryptFinal,
}

trait ChaChaStream: StreamCipher<Error = StreamError> {
    const NONCE_BYTES: usize;

    fn init<P>(&mut self, params: &P) -> Result<(), InitError>
    where
        P: KeyParams + IvParams + ?Sized;
}

impl ChaChaStream for ChaCha7539Engine {
    const NONCE_BYTES: usize = NONCE_BYTES;

    fn init<P>(&mut self, params: &P) -> Result<(), InitError>
    where
        P: KeyParams + IvParams + ?Sized,
    {
        StreamCipherInit::init(self, CipherDirection::Encrypt, params)
    }
}

impl ChaChaStream for XChaCha20Engine {
    const NONCE_BYTES: usize = XNONCE_BYTES;

    fn init<P>(&mut self, params: &P) -> Result<(), InitError>
    where
        P: KeyParams + IvParams + ?Sized,
    {
        StreamCipherInit::init(self, CipherDirection::Encrypt, params)
    }
}

struct MacKey<'a>(&'a [u8]);

impl KeyParams for MacKey<'_> {
    fn key(&self) -> &[u8] {
        self.0
    }
}

struct Core<C> {
    chacha: C,
    poly1305: Poly1305,
    initial_poly1305: Poly1305,
    buffer: [u8; DECRYPT_BUFFER_BYTES],
    buffer_pos: usize,
    key: [u8; KEY_BYTES],
    nonce: [u8; MAX_NONCE_BYTES],
    nonce_len: usize,
    has_key_nonce: bool,
    aad_count: u64,
    initial_aad_count: u64,
    data_count: u64,
    state: State,
    mac: Option<[u8; TAG_BYTES]>,
}

impl<C> Core<C>
where
    C: ChaChaStream,
{
    const fn new(chacha: C) -> Self {
        Self {
            chacha,
            poly1305: Poly1305::new(),
            initial_poly1305: Poly1305::new(),
            buffer: [0; DECRYPT_BUFFER_BYTES],
            buffer_pos: 0,
            key: [0; KEY_BYTES],
            nonce: [0; MAX_NONCE_BYTES],
            nonce_len: 0,
            has_key_nonce: false,
            aad_count: 0,
            initial_aad_count: 0,
            data_count: 0,
            state: State::Uninitialised,
            mac: None,
        }
    }

    fn check_aad(&mut self) -> Result<(), AeadError> {
        self.state = match self.state {
            State::EncryptInit => State::EncryptAad,
            State::DecryptInit => State::DecryptAad,
            State::EncryptAad | State::DecryptAad => self.state,
            State::EncryptData | State::DecryptData => return Err(AeadError::AadAfterData),
            State::EncryptFinal | State::DecryptFinal => {
                return Err(AeadError::AlreadyFinalised);
            }
            State::Uninitialised => return Err(AeadError::NotInitialised),
        };
        Ok(())
    }

    fn current_direction(&self) -> Result<CipherDirection, AeadError> {
        match self.state {
            State::EncryptInit | State::EncryptAad | State::EncryptData => {
                Ok(CipherDirection::Encrypt)
            }
            State::DecryptInit | State::DecryptAad | State::DecryptData => {
                Ok(CipherDirection::Decrypt)
            }
            State::EncryptFinal | State::DecryptFinal => Err(AeadError::AlreadyFinalised),
            State::Uninitialised => Err(AeadError::NotInitialised),
        }
    }

    fn start_data(&mut self) -> Result<CipherDirection, AeadError> {
        match self.state {
            State::EncryptInit | State::EncryptAad => {
                self.finish_aad(State::EncryptData)?;
                Ok(CipherDirection::Encrypt)
            }
            State::DecryptInit | State::DecryptAad => {
                self.finish_aad(State::DecryptData)?;
                Ok(CipherDirection::Decrypt)
            }
            State::EncryptData => Ok(CipherDirection::Encrypt),
            State::DecryptData => Ok(CipherDirection::Decrypt),
            State::EncryptFinal | State::DecryptFinal => Err(AeadError::AlreadyFinalised),
            State::Uninitialised => Err(AeadError::NotInitialised),
        }
    }

    fn finish_aad(&mut self, next: State) -> Result<(), AeadError> {
        self.pad_mac(self.aad_count)?;
        self.state = next;
        Ok(())
    }

    fn finish_data(&mut self, next: State) -> Result<[u8; TAG_BYTES], AeadError> {
        self.pad_mac(self.data_count)?;

        let mut lengths = [0u8; MAC_BLOCK_BYTES];
        lengths[..8].copy_from_slice(&self.aad_count.to_le_bytes());
        lengths[8..].copy_from_slice(&self.data_count.to_le_bytes());
        self.update_mac(&lengths)?;

        let mut tag = [0u8; TAG_BYTES];
        self.poly1305.do_final(&mut tag).map_err(map_mac_error)?;
        self.state = next;
        Ok(tag)
    }

    fn pad_mac(&mut self, count: u64) -> Result<(), AeadError> {
        const ZEROS: [u8; MAC_BLOCK_BYTES - 1] = [0; MAC_BLOCK_BYTES - 1];
        let partial = count as usize & (MAC_BLOCK_BYTES - 1);
        if partial != 0 {
            self.update_mac(&ZEROS[..MAC_BLOCK_BYTES - partial])?;
        }
        Ok(())
    }

    fn update_mac(&mut self, input: &[u8]) -> Result<(), AeadError> {
        self.poly1305.update(input).map_err(map_mac_error)
    }

    fn process_data(&mut self, input: &[u8], output: &mut [u8]) -> Result<(), AeadError> {
        let input_len = input.len() as u64;
        if self.data_count > DATA_LIMIT.saturating_sub(input_len) {
            return Err(AeadError::InputTooLong);
        }
        self.chacha
            .process_bytes(input, output)
            .map_err(map_stream_error)?;
        self.data_count += input_len;
        Ok(())
    }

    fn process_encrypt_bytes(
        &mut self,
        mut input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, AeadError> {
        let mut written = 0;

        if self.buffer_pos != 0 {
            let available = BLOCK_BYTES - self.buffer_pos;
            if input.len() < available {
                self.buffer[self.buffer_pos..self.buffer_pos + input.len()].copy_from_slice(input);
                self.buffer_pos += input.len();
                return Ok(0);
            }

            self.buffer[self.buffer_pos..BLOCK_BYTES].copy_from_slice(&input[..available]);
            input = &input[available..];
            let block: [u8; BLOCK_BYTES] = self.buffer[..BLOCK_BYTES].try_into().unwrap();
            self.process_data(&block, &mut output[..BLOCK_BYTES])?;
            self.update_mac(&output[..BLOCK_BYTES])?;
            written = BLOCK_BYTES;
            self.buffer_pos = 0;
        }

        while input.len() >= BLOCK_BYTES {
            self.process_data(
                &input[..BLOCK_BYTES],
                &mut output[written..written + BLOCK_BYTES],
            )?;
            self.update_mac(&output[written..written + BLOCK_BYTES])?;
            input = &input[BLOCK_BYTES..];
            written += BLOCK_BYTES;
        }

        self.buffer[..input.len()].copy_from_slice(input);
        self.buffer_pos = input.len();
        Ok(written)
    }

    fn process_decrypt_bytes(
        &mut self,
        mut input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, AeadError> {
        let mut written = 0;

        while self.buffer_pos.saturating_add(input.len()) >= DECRYPT_BUFFER_BYTES {
            if self.buffer_pos < BLOCK_BYTES {
                let needed = BLOCK_BYTES - self.buffer_pos;
                self.buffer[self.buffer_pos..BLOCK_BYTES].copy_from_slice(&input[..needed]);
                input = &input[needed..];
                self.buffer_pos = BLOCK_BYTES;
            }

            let block: [u8; BLOCK_BYTES] = self.buffer[..BLOCK_BYTES].try_into().unwrap();
            self.update_mac(&block)?;
            self.process_data(&block, &mut output[written..written + BLOCK_BYTES])?;
            written += BLOCK_BYTES;
            self.buffer.copy_within(BLOCK_BYTES..self.buffer_pos, 0);
            self.buffer_pos -= BLOCK_BYTES;
        }

        self.buffer[self.buffer_pos..self.buffer_pos + input.len()].copy_from_slice(input);
        self.buffer_pos += input.len();
        Ok(written)
    }

    fn process_aad_bytes(&mut self, input: &[u8]) -> Result<(), AeadError> {
        self.check_aad()?;
        self.mac = None;
        let input_len = input.len() as u64;
        self.aad_count = self
            .aad_count
            .checked_add(input_len)
            .ok_or(AeadError::InputTooLong)?;
        self.update_mac(input)
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, AeadError> {
        let direction = self.current_direction()?;
        let required = self.get_update_output_size(input.len());
        if output.len() < required {
            return Err(AeadError::OutputTooShort {
                required,
                available: output.len(),
            });
        }

        let pending_data = match direction {
            CipherDirection::Encrypt => self.buffer_pos.saturating_add(input.len()),
            CipherDirection::Decrypt => self
                .buffer_pos
                .saturating_add(input.len())
                .saturating_sub(TAG_BYTES),
        } as u64;
        if self.data_count > DATA_LIMIT.saturating_sub(pending_data) {
            return Err(AeadError::InputTooLong);
        }

        self.mac = None;
        let started_direction = self.start_data()?;
        debug_assert_eq!(started_direction, direction);
        match direction {
            CipherDirection::Encrypt => self.process_encrypt_bytes(input, output),
            CipherDirection::Decrypt => self.process_decrypt_bytes(input, output),
        }
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AeadError> {
        let direction = self.current_direction()?;
        let required = self.get_output_size(0);
        if output.len() < required {
            return Err(AeadError::OutputTooShort {
                required,
                available: output.len(),
            });
        }
        if direction == CipherDirection::Decrypt && self.buffer_pos < TAG_BYTES {
            self.mac = None;
            return Err(AeadError::CiphertextTooShort {
                minimum: TAG_BYTES,
                actual: self.buffer_pos,
            });
        }

        self.mac = None;
        let started_direction = self.start_data()?;
        debug_assert_eq!(started_direction, direction);

        match direction {
            CipherDirection::Encrypt => {
                let message_len = self.buffer_pos;
                let final_input: [u8; BLOCK_BYTES] = self.buffer[..BLOCK_BYTES].try_into().unwrap();
                self.process_data(&final_input[..message_len], &mut output[..message_len])?;
                self.update_mac(&output[..message_len])?;
                let tag = self.finish_data(State::EncryptFinal)?;
                output[message_len..message_len + TAG_BYTES].copy_from_slice(&tag);
                self.mac = Some(tag);
                self.clear_buffer();
                Ok(message_len + TAG_BYTES)
            }
            CipherDirection::Decrypt => {
                let message_len = self.buffer_pos - TAG_BYTES;
                let final_input: [u8; BLOCK_BYTES] = self.buffer[..BLOCK_BYTES].try_into().unwrap();
                self.update_mac(&final_input[..message_len])?;
                self.process_data(&final_input[..message_len], &mut output[..message_len])?;
                let mut expected_tag = self.finish_data(State::DecryptFinal)?;
                let mut received_tag = [0u8; TAG_BYTES];
                received_tag.copy_from_slice(&self.buffer[message_len..message_len + TAG_BYTES]);
                self.clear_buffer();

                if !fixed_time_eq(&expected_tag, &received_tag) {
                    output[..message_len].fill(0);
                    expected_tag.fill(0);
                    received_tag.fill(0);
                    return Err(AeadError::AuthenticationFailed);
                }

                expected_tag.fill(0);
                self.mac = Some(received_tag);
                Ok(message_len)
            }
        }
    }

    fn mac(&self) -> Option<&[u8]> {
        self.mac.as_ref().map(|mac| mac.as_slice())
    }

    fn get_update_output_size(&self, input_len: usize) -> usize {
        let total = match self.state {
            State::DecryptInit | State::DecryptAad => input_len.saturating_sub(TAG_BYTES),
            State::DecryptData | State::DecryptFinal => self
                .buffer_pos
                .saturating_add(input_len)
                .saturating_sub(TAG_BYTES),
            State::EncryptData | State::EncryptFinal => self.buffer_pos.saturating_add(input_len),
            State::Uninitialised | State::EncryptInit | State::EncryptAad => input_len,
        };
        total - total % BLOCK_BYTES
    }

    fn get_output_size(&self, input_len: usize) -> usize {
        match self.state {
            State::DecryptInit | State::DecryptAad => input_len.saturating_sub(TAG_BYTES),
            State::DecryptData | State::DecryptFinal => self
                .buffer_pos
                .saturating_add(input_len)
                .saturating_sub(TAG_BYTES),
            State::EncryptData | State::EncryptFinal => self
                .buffer_pos
                .saturating_add(input_len)
                .saturating_add(TAG_BYTES),
            State::Uninitialised | State::EncryptInit | State::EncryptAad => {
                input_len.saturating_add(TAG_BYTES)
            }
        }
    }

    fn init<P>(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError>
    where
        P: KeyParams + IvParams + InitialAadParams + ?Sized,
    {
        let key = params.key();
        if key.len() != KEY_BYTES {
            return Err(InitError::InvalidKeyLength(key.len()));
        }
        let nonce = params.iv();
        if nonce.len() != C::NONCE_BYTES {
            return Err(InitError::InvalidIvLength(nonce.len()));
        }

        if direction == CipherDirection::Encrypt
            && self.has_key_nonce
            && self.key == key
            && self.nonce_len == nonce.len()
            && self.nonce[..self.nonce_len] == *nonce
        {
            return Err(InitError::NonceReuse);
        }

        self.state = State::Uninitialised;
        self.mac = None;
        self.clear_buffer();
        self.aad_count = 0;
        self.data_count = 0;

        self.chacha.init(params)?;

        let zeros = [0u8; BLOCK_BYTES];
        let mut first_block = [0u8; BLOCK_BYTES];
        self.chacha
            .process_bytes(&zeros, &mut first_block)
            .map_err(|_| InitError::InternalFailure)?;
        self.poly1305
            .init(&MacKey(&first_block[..tc_poly1305::KEY_BYTES]))
            .map_err(|_| InitError::InternalFailure)?;
        first_block.fill(0);

        self.key.copy_from_slice(key);
        self.nonce.fill(0);
        self.nonce[..nonce.len()].copy_from_slice(nonce);
        self.nonce_len = nonce.len();
        self.has_key_nonce = true;
        self.state = match direction {
            CipherDirection::Encrypt => State::EncryptInit,
            CipherDirection::Decrypt => State::DecryptInit,
        };

        let initial_aad = params.initial_aad();
        if !initial_aad.is_empty() {
            self.state = match direction {
                CipherDirection::Encrypt => State::EncryptAad,
                CipherDirection::Decrypt => State::DecryptAad,
            };
            self.aad_count = initial_aad.len() as u64;
            self.poly1305
                .update(initial_aad)
                .map_err(|_| InitError::InternalFailure)?;
        }
        self.initial_aad_count = self.aad_count;
        self.initial_poly1305 = self.poly1305.clone();
        Ok(())
    }

    fn clear_buffer(&mut self) {
        self.buffer.fill(0);
        self.buffer_pos = 0;
    }

    fn restore_initial_state(&mut self, direction: CipherDirection) {
        self.clear_buffer();
        self.aad_count = self.initial_aad_count;
        self.data_count = 0;
        self.chacha.reset();

        let zeros = [0u8; BLOCK_BYTES];
        let mut first_block = [0u8; BLOCK_BYTES];
        if self.chacha.process_bytes(&zeros, &mut first_block).is_err() {
            self.state = State::Uninitialised;
            return;
        }
        first_block.fill(0);
        self.poly1305 = self.initial_poly1305.clone();
        self.state = match (direction, self.initial_aad_count) {
            (CipherDirection::Encrypt, 0) => State::EncryptInit,
            (CipherDirection::Encrypt, _) => State::EncryptAad,
            (CipherDirection::Decrypt, 0) => State::DecryptInit,
            (CipherDirection::Decrypt, _) => State::DecryptAad,
        };
    }

    fn reset(&mut self) {
        self.mac = None;
        self.clear_buffer();
        match self.state {
            State::EncryptInit => self.restore_initial_state(CipherDirection::Encrypt),
            State::EncryptAad | State::EncryptData | State::EncryptFinal => {
                self.aad_count = 0;
                self.data_count = 0;
                self.state = State::EncryptFinal;
            }
            State::DecryptInit | State::DecryptAad | State::DecryptData | State::DecryptFinal => {
                self.restore_initial_state(CipherDirection::Decrypt)
            }
            State::Uninitialised => {
                self.aad_count = 0;
                self.data_count = 0;
            }
        }
    }
}

/// RFC 8439 ChaCha20-Poly1305 authenticated encryption.
///
/// Encryption rejects reuse of the same key and nonce on one engine instance.
/// Decryption retains the trailing 16-byte tag and verifies it during
/// finalization. Plaintext emitted before successful finalization is
/// unauthenticated and must not be released to consumers.
pub struct ChaCha20Poly1305 {
    core: Core<ChaCha7539Engine>,
}

impl ChaCha20Poly1305 {
    /// Creates an uninitialized ChaCha20-Poly1305 engine.
    pub const fn new() -> Self {
        Self {
            core: Core::new(ChaCha7539Engine::new()),
        }
    }
}

impl Default for ChaCha20Poly1305 {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for ChaCha20Poly1305 {
    fn write_algo_name(&self, output: &mut dyn fmt::Write) -> fmt::Result {
        output.write_str("ChaCha20Poly1305")
    }
}

impl AeadCipher for ChaCha20Poly1305 {
    type Error = AeadError;

    fn process_aad_bytes(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.core.process_aad_bytes(input)
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        self.core.process_bytes(input, output)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.core.do_final(output)
    }

    fn mac(&self) -> Option<&[u8]> {
        self.core.mac()
    }

    fn reset(&mut self) {
        self.core.reset();
    }

    fn get_update_output_size(&self, input_len: usize) -> usize {
        self.core.get_update_output_size(input_len)
    }

    fn get_output_size(&self, input_len: usize) -> usize {
        self.core.get_output_size(input_len)
    }
}

impl<P> AeadCipherInit<P> for ChaCha20Poly1305
where
    P: KeyParams + IvParams + InitialAadParams + ?Sized,
{
    type Error = InitError;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.core.init(direction, params)
    }
}

/// XChaCha20-Poly1305 authenticated encryption with a 192-bit nonce.
///
/// This construction uses HChaCha20 to derive a subkey, then reuses the same
/// AEAD processing core as RFC 8439 ChaCha20-Poly1305. Encryption rejects
/// reuse of the same key and nonce on one engine instance.
pub struct XChaCha20Poly1305 {
    core: Core<XChaCha20Engine>,
}

impl XChaCha20Poly1305 {
    /// Creates an uninitialized XChaCha20-Poly1305 engine.
    pub const fn new() -> Self {
        Self {
            core: Core::new(XChaCha20Engine::new()),
        }
    }
}

impl Default for XChaCha20Poly1305 {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for XChaCha20Poly1305 {
    fn write_algo_name(&self, output: &mut dyn fmt::Write) -> fmt::Result {
        output.write_str("XChaCha20Poly1305")
    }
}

impl AeadCipher for XChaCha20Poly1305 {
    type Error = AeadError;

    fn process_aad_bytes(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.core.process_aad_bytes(input)
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        self.core.process_bytes(input, output)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.core.do_final(output)
    }

    fn mac(&self) -> Option<&[u8]> {
        self.core.mac()
    }

    fn reset(&mut self) {
        self.core.reset();
    }

    fn get_update_output_size(&self, input_len: usize) -> usize {
        self.core.get_update_output_size(input_len)
    }

    fn get_output_size(&self, input_len: usize) -> usize {
        self.core.get_output_size(input_len)
    }
}

impl<P> AeadCipherInit<P> for XChaCha20Poly1305
where
    P: KeyParams + IvParams + InitialAadParams + ?Sized,
{
    type Error = InitError;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.core.init(direction, params)
    }
}

fn map_mac_error(error: MacError) -> AeadError {
    match error {
        MacError::NotInitialised => AeadError::NotInitialised,
        MacError::OutputTooShort {
            required,
            available,
        } => AeadError::OutputTooShort {
            required,
            available,
        },
        _ => AeadError::InternalFailure,
    }
}

fn map_stream_error(error: StreamError) -> AeadError {
    match error {
        StreamError::NotInitialised => AeadError::NotInitialised,
        StreamError::BufferTooShort => AeadError::InternalFailure,
        StreamError::MaxBytesExceeded | StreamError::CounterExhausted => AeadError::InputTooLong,
        _ => AeadError::InternalFailure,
    }
}

fn fixed_time_eq(left: &[u8; TAG_BYTES], right: &[u8; TAG_BYTES]) -> bool {
    let mut difference = 0u8;
    for (&left, &right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}
