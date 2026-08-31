//! Ascon-AEAD128 authenticated-encryption engine.

use tc_cipher_core::{AeadCipher, AeadCipherInit, CipherDirection};

use super::{Params, TAG_BYTES};
use crate::AeadCipherError;

const ASCON_IV: u64 = 0x0000_1000_808c_0001;
const RATE: usize = 16;
const DECRYPT_BUFFER_BYTES: usize = RATE + TAG_BYTES;

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

/// Incremental Ascon-AEAD128 engine from NIST SP 800-232.
///
/// The engine does not allocate. Encryption appends the fixed 16-byte tag from
/// [`AeadCipher::do_final`]. Decryption retains the trailing 16 input bytes as
/// the prospective tag and verifies them during finalization.
///
/// A key/nonce pair must never be reused for encryption. After either
/// direction is finalized, call [`AeadCipherInit::init`] with fresh parameters
/// before processing another message.
pub struct Engine {
    buffer: [u8; DECRYPT_BUFFER_BYTES],
    buffer_pos: usize,
    key: [u64; 2],
    nonce: [u64; 2],
    state_words: [u64; 5],
    state: State,
    mac: Option<[u8; TAG_BYTES]>,
}

impl Engine {
    /// Creates an uninitialised engine.
    pub const fn new() -> Self {
        Self {
            buffer: [0; DECRYPT_BUFFER_BYTES],
            buffer_pos: 0,
            key: [0; 2],
            nonce: [0; 2],
            state_words: [0; 5],
            state: State::Uninitialised,
            mac: None,
        }
    }

    fn initialise_state(&mut self) {
        self.state_words = [
            ASCON_IV,
            self.key[0],
            self.key[1],
            self.nonce[0],
            self.nonce[1],
        ];
        self.permute_12();
        self.state_words[3] ^= self.key[0];
        self.state_words[4] ^= self.key[1];
    }

    fn check_aad(&mut self) -> Result<(), AeadCipherError> {
        self.state = match self.state {
            State::EncryptInit => State::EncryptAad,
            State::DecryptInit => State::DecryptAad,
            State::EncryptAad | State::DecryptAad => self.state,
            State::EncryptData | State::DecryptData => {
                return Err(AeadCipherError::AadAfterData);
            }
            State::EncryptFinal | State::DecryptFinal => {
                return Err(AeadCipherError::AlreadyFinalised);
            }
            State::Uninitialised => return Err(AeadCipherError::NotInitialised),
        };
        Ok(())
    }

    fn current_direction(&self) -> Result<CipherDirection, AeadCipherError> {
        match self.state {
            State::EncryptInit | State::EncryptAad | State::EncryptData => {
                Ok(CipherDirection::Encrypt)
            }
            State::DecryptInit | State::DecryptAad | State::DecryptData => {
                Ok(CipherDirection::Decrypt)
            }
            State::EncryptFinal | State::DecryptFinal => Err(AeadCipherError::AlreadyFinalised),
            State::Uninitialised => Err(AeadCipherError::NotInitialised),
        }
    }

    fn start_data(&mut self) -> Result<CipherDirection, AeadCipherError> {
        match self.state {
            State::EncryptInit | State::EncryptAad => {
                self.finish_aad(State::EncryptData);
                Ok(CipherDirection::Encrypt)
            }
            State::DecryptInit | State::DecryptAad => {
                self.finish_aad(State::DecryptData);
                Ok(CipherDirection::Decrypt)
            }
            State::EncryptData => Ok(CipherDirection::Encrypt),
            State::DecryptData => Ok(CipherDirection::Decrypt),
            State::EncryptFinal | State::DecryptFinal => Err(AeadCipherError::AlreadyFinalised),
            State::Uninitialised => Err(AeadCipherError::NotInitialised),
        }
    }

    fn finish_aad(&mut self, next: State) {
        if matches!(self.state, State::EncryptAad | State::DecryptAad) {
            let mut final_block = [0_u8; RATE];
            final_block[..self.buffer_pos].copy_from_slice(&self.buffer[..self.buffer_pos]);
            final_block[self.buffer_pos] = 0x01;
            self.state_words[0] ^= load_u64(&final_block[..8]);
            self.state_words[1] ^= load_u64(&final_block[8..]);
            self.permute_8();
        }

        self.state_words[4] ^= 0x8000_0000_0000_0000;
        self.buffer.fill(0);
        self.buffer_pos = 0;
        self.state = next;
    }

    fn finish_data(&mut self, next: State) {
        self.state_words[2] ^= self.key[0];
        self.state_words[3] ^= self.key[1];
        self.permute_12();
        self.state_words[3] ^= self.key[0];
        self.state_words[4] ^= self.key[1];
        self.state = next;
    }

    fn process_aad_block(&mut self, block: &[u8; RATE]) {
        self.state_words[0] ^= load_u64(&block[..8]);
        self.state_words[1] ^= load_u64(&block[8..]);
        self.permute_8();
    }

    fn process_encrypt_block(&mut self, block: &[u8; RATE], output: &mut [u8]) {
        self.state_words[0] ^= load_u64(&block[..8]);
        output[..8].copy_from_slice(&self.state_words[0].to_le_bytes());
        self.state_words[1] ^= load_u64(&block[8..]);
        output[8..RATE].copy_from_slice(&self.state_words[1].to_le_bytes());
        self.permute_8();
    }

    fn process_decrypt_block(&mut self, block: &[u8; RATE], output: &mut [u8]) {
        let ciphertext_0 = load_u64(&block[..8]);
        output[..8].copy_from_slice(&(self.state_words[0] ^ ciphertext_0).to_le_bytes());
        self.state_words[0] = ciphertext_0;

        let ciphertext_1 = load_u64(&block[8..]);
        output[8..RATE].copy_from_slice(&(self.state_words[1] ^ ciphertext_1).to_le_bytes());
        self.state_words[1] = ciphertext_1;
        self.permute_8();
    }

    fn process_encrypt_bytes(&mut self, mut input: &[u8], output: &mut [u8]) -> usize {
        let mut written = 0;

        if self.buffer_pos > 0 {
            let available = RATE - self.buffer_pos;
            if input.len() < available {
                self.buffer[self.buffer_pos..self.buffer_pos + input.len()].copy_from_slice(input);
                self.buffer_pos += input.len();
                return 0;
            }

            self.buffer[self.buffer_pos..RATE].copy_from_slice(&input[..available]);
            input = &input[available..];
            let block: [u8; RATE] = self.buffer[..RATE].try_into().unwrap();
            self.process_encrypt_block(&block, &mut output[..RATE]);
            written = RATE;
            self.buffer_pos = 0;
        }

        while input.len() >= RATE {
            let block: &[u8; RATE] = input[..RATE].try_into().unwrap();
            self.process_encrypt_block(block, &mut output[written..written + RATE]);
            input = &input[RATE..];
            written += RATE;
        }

        self.buffer[..input.len()].copy_from_slice(input);
        self.buffer_pos = input.len();
        written
    }

    fn process_decrypt_bytes(&mut self, mut input: &[u8], output: &mut [u8]) -> usize {
        let mut written = 0;

        // Emit complete rate blocks only while a full trailing tag remains
        // across the buffered bytes and the new input.
        while self.buffer_pos.saturating_add(input.len()) >= DECRYPT_BUFFER_BYTES {
            if self.buffer_pos < RATE {
                let needed = RATE - self.buffer_pos;
                self.buffer[self.buffer_pos..RATE].copy_from_slice(&input[..needed]);
                input = &input[needed..];
                self.buffer_pos = RATE;
            }

            let block: [u8; RATE] = self.buffer[..RATE].try_into().unwrap();
            self.process_decrypt_block(&block, &mut output[written..written + RATE]);
            written += RATE;
            self.buffer.copy_within(RATE..self.buffer_pos, 0);
            self.buffer_pos -= RATE;
        }

        self.buffer[self.buffer_pos..self.buffer_pos + input.len()].copy_from_slice(input);
        self.buffer_pos += input.len();
        written
    }

    fn process_final_encrypt(&mut self, input: &[u8], output: &mut [u8]) {
        debug_assert!(input.len() < RATE);
        for (index, (&input_byte, output_byte)) in input.iter().zip(output.iter_mut()).enumerate() {
            let lane = index / 8;
            let shift = (index % 8) * 8;
            self.state_words[lane] ^= u64::from(input_byte) << shift;
            *output_byte = (self.state_words[lane] >> shift) as u8;
        }
        self.state_words[input.len() / 8] ^= 1_u64 << ((input.len() % 8) * 8);
        self.finish_data(State::EncryptFinal);
    }

    fn process_final_decrypt(&mut self, input: &[u8], output: &mut [u8]) {
        debug_assert!(input.len() < RATE);
        for (index, (&ciphertext_byte, output_byte)) in
            input.iter().zip(output.iter_mut()).enumerate()
        {
            let lane = index / 8;
            let shift = (index % 8) * 8;
            *output_byte = ((self.state_words[lane] >> shift) as u8) ^ ciphertext_byte;
            let mask = 0xff_u64 << shift;
            self.state_words[lane] =
                (self.state_words[lane] & !mask) | (u64::from(ciphertext_byte) << shift);
        }
        self.state_words[input.len() / 8] ^= 1_u64 << ((input.len() % 8) * 8);
        self.finish_data(State::DecryptFinal);
    }

    fn permute_8(&mut self) {
        for constant in [0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b] {
            self.round(constant);
        }
    }

    fn permute_12(&mut self) {
        for constant in [
            0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
        ] {
            self.round(constant);
        }
    }

    #[inline]
    fn round(&mut self, constant: u64) {
        let sx = self.state_words[2] ^ constant;
        let t0 = self.state_words[0]
            ^ self.state_words[1]
            ^ sx
            ^ self.state_words[3]
            ^ (self.state_words[1] & (self.state_words[0] ^ sx ^ self.state_words[4]));
        let t1 = self.state_words[0]
            ^ sx
            ^ self.state_words[3]
            ^ self.state_words[4]
            ^ ((self.state_words[1] ^ sx) & (self.state_words[1] ^ self.state_words[3]));
        let t2 = self.state_words[1]
            ^ sx
            ^ self.state_words[4]
            ^ (self.state_words[3] & self.state_words[4]);
        let t3 = self.state_words[0]
            ^ self.state_words[1]
            ^ sx
            ^ (!self.state_words[0] & (self.state_words[3] ^ self.state_words[4]));
        let t4 = self.state_words[1]
            ^ self.state_words[3]
            ^ self.state_words[4]
            ^ ((self.state_words[0] ^ self.state_words[4]) & self.state_words[1]);

        self.state_words[0] = t0 ^ t0.rotate_right(19) ^ t0.rotate_right(28);
        self.state_words[1] = t1 ^ t1.rotate_right(39) ^ t1.rotate_right(61);
        self.state_words[2] = !(t2 ^ t2.rotate_right(1) ^ t2.rotate_right(6));
        self.state_words[3] = t3 ^ t3.rotate_right(10) ^ t3.rotate_right(17);
        self.state_words[4] = t4 ^ t4.rotate_right(7) ^ t4.rotate_right(41);
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl AeadCipher for Engine {
    type Error = AeadCipherError;

    fn algorithm_name(&self) -> &str {
        "Ascon-AEAD128"
    }

    fn process_aad_bytes(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        if input.is_empty() {
            return Ok(());
        }
        self.check_aad()?;
        self.mac = None;

        if self.buffer_pos > 0 {
            let available = RATE - self.buffer_pos;
            if input.len() < available {
                self.buffer[self.buffer_pos..self.buffer_pos + input.len()].copy_from_slice(input);
                self.buffer_pos += input.len();
                return Ok(());
            }

            self.buffer[self.buffer_pos..RATE].copy_from_slice(&input[..available]);
            input = &input[available..];
            let block: [u8; RATE] = self.buffer[..RATE].try_into().unwrap();
            self.process_aad_block(&block);
            self.buffer_pos = 0;
        }

        while input.len() >= RATE {
            let block: &[u8; RATE] = input[..RATE].try_into().unwrap();
            self.process_aad_block(block);
            input = &input[RATE..];
        }

        self.buffer[..input.len()].copy_from_slice(input);
        self.buffer_pos = input.len();
        Ok(())
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let direction = self.current_direction()?;
        let required = self.get_update_output_size(input.len());
        if output.len() < required {
            return Err(AeadCipherError::OutputBufferTooShort {
                required,
                actual: output.len(),
            });
        }

        self.mac = None;
        debug_assert_eq!(self.start_data()?, direction);
        Ok(match direction {
            CipherDirection::Encrypt => self.process_encrypt_bytes(input, output),
            CipherDirection::Decrypt => self.process_decrypt_bytes(input, output),
        })
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let direction = self.current_direction()?;
        let required = self.get_output_size(0);
        if output.len() < required {
            return Err(AeadCipherError::OutputBufferTooShort {
                required,
                actual: output.len(),
            });
        }

        if direction == CipherDirection::Decrypt && self.buffer_pos < TAG_BYTES {
            self.mac = None;
            return Err(AeadCipherError::CiphertextTooShort {
                minimum: TAG_BYTES,
                actual: self.buffer_pos,
            });
        }

        self.mac = None;
        debug_assert_eq!(self.start_data()?, direction);
        match direction {
            CipherDirection::Encrypt => {
                let message_len = self.buffer_pos;
                let final_input: [u8; RATE] = self.buffer[..RATE].try_into().unwrap();
                self.process_final_encrypt(&final_input[..message_len], &mut output[..message_len]);

                let mut tag = [0_u8; TAG_BYTES];
                tag[..8].copy_from_slice(&self.state_words[3].to_le_bytes());
                tag[8..].copy_from_slice(&self.state_words[4].to_le_bytes());
                output[message_len..message_len + TAG_BYTES].copy_from_slice(&tag);
                self.mac = Some(tag);
                self.buffer.fill(0);
                self.buffer_pos = 0;
                Ok(message_len + TAG_BYTES)
            }
            CipherDirection::Decrypt => {
                let message_len = self.buffer_pos - TAG_BYTES;
                let mut received_tag = [0_u8; TAG_BYTES];
                received_tag.copy_from_slice(&self.buffer[message_len..message_len + TAG_BYTES]);
                let final_input: [u8; RATE] = self.buffer[..RATE].try_into().unwrap();
                self.process_final_decrypt(&final_input[..message_len], &mut output[..message_len]);

                let mut expected_tag = [0_u8; TAG_BYTES];
                expected_tag[..8].copy_from_slice(&self.state_words[3].to_le_bytes());
                expected_tag[8..].copy_from_slice(&self.state_words[4].to_le_bytes());
                self.buffer.fill(0);
                self.buffer_pos = 0;

                if !fixed_time_eq(&expected_tag, &received_tag) {
                    output[..message_len].fill(0);
                    return Err(AeadCipherError::AuthenticationFailed);
                }

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
        total - total % RATE
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
}

impl AeadCipherInit for Engine {
    type Params<'a> = dyn Params + 'a;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        let key = params.key();
        let nonce = params.nonce();
        self.key[0] = load_u64(&key[..8]);
        self.key[1] = load_u64(&key[8..]);
        self.nonce[0] = load_u64(&nonce[..8]);
        self.nonce[1] = load_u64(&nonce[8..]);
        self.buffer.fill(0);
        self.buffer_pos = 0;
        self.mac = None;
        self.state = match direction {
            CipherDirection::Encrypt => State::EncryptInit,
            CipherDirection::Decrypt => State::DecryptInit,
        };
        self.initialise_state();
        self.process_aad_bytes(params.initial_aad())
    }
}

fn load_u64(input: &[u8]) -> u64 {
    u64::from_le_bytes(input[..8].try_into().unwrap())
}

fn fixed_time_eq(a: &[u8; TAG_BYTES], b: &[u8; TAG_BYTES]) -> bool {
    let mut difference = 0_u8;
    for (&left, &right) in a.iter().zip(b) {
        difference |= left ^ right;
    }
    difference == 0
}
