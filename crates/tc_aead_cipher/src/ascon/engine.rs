//! Incremental legacy Ascon v1.2 AEAD engine.

use tc_cipher_core::{AeadCipher, AeadCipherInit, CipherDirection};

use super::{KEY_BYTES_80PQ, KEY_BYTES_128, NONCE_BYTES, Params, TAG_BYTES, Variant};
use crate::AeadCipherError;

const MAX_RATE: usize = 16;
const MAX_DECRYPT_BUFFER_BYTES: usize = MAX_RATE + TAG_BYTES;

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

/// Incremental engine for the legacy Ascon v1.2 AEAD variants.
///
/// This family is retained for compatibility with the pre-standard
/// Ascon-128, Ascon-128a, and Ascon-80pq algorithms. New protocols should use
/// [`crate::ascon_aead128::Engine`], which implements NIST SP 800-232.
///
/// Encryption appends a 16-byte authentication tag. Decryption may emit
/// unauthenticated plaintext before [`AeadCipher::do_final`] verifies the tag;
/// callers must not release that plaintext before finalization succeeds.
pub struct Engine {
    variant: Variant,
    buffer: [u8; MAX_DECRYPT_BUFFER_BYTES],
    buffer_pos: usize,
    key: [u64; 3],
    nonce: [u64; 2],
    state_words: [u64; 5],
    state: State,
    mac: Option<[u8; TAG_BYTES]>,
}

impl Engine {
    /// Creates an uninitialised engine for `variant`.
    pub const fn new(variant: Variant) -> Self {
        Self {
            variant,
            buffer: [0; MAX_DECRYPT_BUFFER_BYTES],
            buffer_pos: 0,
            key: [0; 3],
            nonce: [0; 2],
            state_words: [0; 5],
            state: State::Uninitialised,
            mac: None,
        }
    }

    /// Returns the selected legacy Ascon variant.
    pub const fn variant(&self) -> Variant {
        self.variant
    }

    /// Returns the required key length for the selected variant.
    pub const fn key_bytes(&self) -> usize {
        self.variant.key_bytes()
    }

    /// Returns the required nonce length.
    pub const fn nonce_bytes(&self) -> usize {
        NONCE_BYTES
    }

    /// Returns the authentication-tag length.
    pub const fn tag_bytes(&self) -> usize {
        TAG_BYTES
    }

    fn rate(&self) -> usize {
        self.variant.rate()
    }

    fn decrypt_buffer_bytes(&self) -> usize {
        self.rate() + TAG_BYTES
    }

    fn initialise_state(&mut self) {
        self.state_words = [
            self.variant.initialisation_value(),
            self.key[1],
            self.key[2],
            self.nonce[0],
            self.nonce[1],
        ];
        if self.variant == Variant::Ascon80pq {
            self.state_words[0] ^= self.key[0];
        }
        self.permute(12);
        if self.variant == Variant::Ascon80pq {
            self.state_words[2] ^= self.key[0];
        }
        self.state_words[3] ^= self.key[1];
        self.state_words[4] ^= self.key[2];
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
            let rate = self.rate();
            let mut final_block = [0_u8; MAX_RATE];
            final_block[..self.buffer_pos].copy_from_slice(&self.buffer[..self.buffer_pos]);
            final_block[self.buffer_pos] = 0x80;
            self.state_words[0] ^= load_u64(&final_block[..8]);
            if rate == MAX_RATE {
                self.state_words[1] ^= load_u64(&final_block[8..]);
            }
            self.permute(self.variant.rounds());
        }

        self.state_words[4] ^= 1;
        self.buffer.fill(0);
        self.buffer_pos = 0;
        self.state = next;
    }

    fn finish_data(&mut self, next: State) {
        match self.variant {
            Variant::Ascon128 => {
                self.state_words[1] ^= self.key[1];
                self.state_words[2] ^= self.key[2];
            }
            Variant::Ascon128a => {
                self.state_words[2] ^= self.key[1];
                self.state_words[3] ^= self.key[2];
            }
            Variant::Ascon80pq => {
                self.state_words[1] ^= (self.key[0] << 32) | (self.key[1] >> 32);
                self.state_words[2] ^= (self.key[1] << 32) | (self.key[2] >> 32);
                self.state_words[3] ^= self.key[2] << 32;
            }
        }
        self.permute(12);
        self.state_words[3] ^= self.key[1];
        self.state_words[4] ^= self.key[2];
        self.state = next;
    }

    fn process_aad_block(&mut self, block: &[u8]) {
        let rate = self.rate();
        debug_assert!(block.len() >= rate);
        self.state_words[0] ^= load_u64(&block[..8]);
        if rate == MAX_RATE {
            self.state_words[1] ^= load_u64(&block[8..MAX_RATE]);
        }
        self.permute(self.variant.rounds());
    }

    fn process_encrypt_block(&mut self, block: &[u8], output: &mut [u8]) {
        let rate = self.rate();
        debug_assert!(block.len() >= rate);
        self.state_words[0] ^= load_u64(&block[..8]);
        output[..8].copy_from_slice(&self.state_words[0].to_be_bytes());
        if rate == MAX_RATE {
            self.state_words[1] ^= load_u64(&block[8..MAX_RATE]);
            output[8..MAX_RATE].copy_from_slice(&self.state_words[1].to_be_bytes());
        }
        self.permute(self.variant.rounds());
    }

    fn process_decrypt_block(&mut self, block: &[u8], output: &mut [u8]) {
        let rate = self.rate();
        debug_assert!(block.len() >= rate);
        let ciphertext_0 = load_u64(&block[..8]);
        output[..8].copy_from_slice(&(self.state_words[0] ^ ciphertext_0).to_be_bytes());
        self.state_words[0] = ciphertext_0;
        if rate == MAX_RATE {
            let ciphertext_1 = load_u64(&block[8..MAX_RATE]);
            output[8..MAX_RATE]
                .copy_from_slice(&(self.state_words[1] ^ ciphertext_1).to_be_bytes());
            self.state_words[1] = ciphertext_1;
        }
        self.permute(self.variant.rounds());
    }

    fn process_encrypt_bytes(&mut self, mut input: &[u8], output: &mut [u8]) -> usize {
        let rate = self.rate();
        let mut written = 0;

        if self.buffer_pos > 0 {
            let available = rate - self.buffer_pos;
            if input.len() < available {
                self.buffer[self.buffer_pos..self.buffer_pos + input.len()].copy_from_slice(input);
                self.buffer_pos += input.len();
                return 0;
            }

            self.buffer[self.buffer_pos..rate].copy_from_slice(&input[..available]);
            input = &input[available..];
            let block = self.buffer;
            self.process_encrypt_block(&block[..rate], &mut output[..rate]);
            written = rate;
            self.buffer_pos = 0;
        }

        while input.len() >= rate {
            self.process_encrypt_block(&input[..rate], &mut output[written..written + rate]);
            input = &input[rate..];
            written += rate;
        }

        self.buffer[..input.len()].copy_from_slice(input);
        self.buffer_pos = input.len();
        written
    }

    fn process_decrypt_bytes(&mut self, mut input: &[u8], output: &mut [u8]) -> usize {
        let rate = self.rate();
        let decrypt_buffer_bytes = self.decrypt_buffer_bytes();
        let mut written = 0;

        while self.buffer_pos.saturating_add(input.len()) >= decrypt_buffer_bytes {
            if self.buffer_pos < rate {
                let needed = rate - self.buffer_pos;
                self.buffer[self.buffer_pos..rate].copy_from_slice(&input[..needed]);
                input = &input[needed..];
                self.buffer_pos = rate;
            }

            let block = self.buffer;
            self.process_decrypt_block(&block[..rate], &mut output[written..written + rate]);
            written += rate;
            self.buffer.copy_within(rate..self.buffer_pos, 0);
            self.buffer_pos -= rate;
        }

        self.buffer[self.buffer_pos..self.buffer_pos + input.len()].copy_from_slice(input);
        self.buffer_pos += input.len();
        written
    }

    fn process_final_encrypt(&mut self, input: &[u8], output: &mut [u8]) {
        debug_assert!(input.len() < self.rate());
        for (index, (&input_byte, output_byte)) in input.iter().zip(output.iter_mut()).enumerate() {
            let lane = index / 8;
            let shift = (7 - index % 8) * 8;
            self.state_words[lane] ^= u64::from(input_byte) << shift;
            *output_byte = (self.state_words[lane] >> shift) as u8;
        }
        let pad_index = input.len();
        let lane = pad_index / 8;
        let shift = (7 - pad_index % 8) * 8;
        self.state_words[lane] ^= 0x80_u64 << shift;
        self.finish_data(State::EncryptFinal);
    }

    fn process_final_decrypt(&mut self, input: &[u8], output: &mut [u8]) {
        debug_assert!(input.len() < self.rate());
        for (index, (&ciphertext_byte, output_byte)) in
            input.iter().zip(output.iter_mut()).enumerate()
        {
            let lane = index / 8;
            let shift = (7 - index % 8) * 8;
            *output_byte = ((self.state_words[lane] >> shift) as u8) ^ ciphertext_byte;
            let mask = 0xff_u64 << shift;
            self.state_words[lane] =
                (self.state_words[lane] & !mask) | (u64::from(ciphertext_byte) << shift);
        }
        let pad_index = input.len();
        let lane = pad_index / 8;
        let shift = (7 - pad_index % 8) * 8;
        self.state_words[lane] ^= 0x80_u64 << shift;
        self.finish_data(State::DecryptFinal);
    }

    fn permute(&mut self, rounds: usize) {
        const CONSTANTS: [u64; 12] = [
            0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
        ];
        for constant in &CONSTANTS[CONSTANTS.len() - rounds..] {
            self.round(*constant);
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

impl AeadCipher for Engine {
    type Error = AeadCipherError;

    fn algorithm_name(&self) -> &str {
        self.variant.algorithm_name()
    }

    fn process_aad_bytes(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        if input.is_empty() {
            return Ok(());
        }
        self.check_aad()?;
        self.mac = None;
        let rate = self.rate();

        if self.buffer_pos > 0 {
            let available = rate - self.buffer_pos;
            if input.len() < available {
                self.buffer[self.buffer_pos..self.buffer_pos + input.len()].copy_from_slice(input);
                self.buffer_pos += input.len();
                return Ok(());
            }

            self.buffer[self.buffer_pos..rate].copy_from_slice(&input[..available]);
            input = &input[available..];
            let block = self.buffer;
            self.process_aad_block(&block[..rate]);
            self.buffer_pos = 0;
        }

        while input.len() >= rate {
            self.process_aad_block(&input[..rate]);
            input = &input[rate..];
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
                let final_input = self.buffer;
                self.process_final_encrypt(&final_input[..message_len], &mut output[..message_len]);

                let mut tag = [0_u8; TAG_BYTES];
                tag[..8].copy_from_slice(&self.state_words[3].to_be_bytes());
                tag[8..].copy_from_slice(&self.state_words[4].to_be_bytes());
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
                let final_input = self.buffer;
                self.process_final_decrypt(&final_input[..message_len], &mut output[..message_len]);

                let mut expected_tag = [0_u8; TAG_BYTES];
                expected_tag[..8].copy_from_slice(&self.state_words[3].to_be_bytes());
                expected_tag[8..].copy_from_slice(&self.state_words[4].to_be_bytes());
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
        let rate = self.rate();
        total - total % rate
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
        if key.len() != self.variant.key_bytes() {
            return Err(AeadCipherError::InvalidKeyLength(key.len()));
        }

        self.key.fill(0);
        match self.variant {
            Variant::Ascon128 | Variant::Ascon128a => {
                debug_assert_eq!(key.len(), KEY_BYTES_128);
                self.key[1] = load_u64(&key[..8]);
                self.key[2] = load_u64(&key[8..]);
            }
            Variant::Ascon80pq => {
                debug_assert_eq!(key.len(), KEY_BYTES_80PQ);
                self.key[0] = u64::from(u32::from_be_bytes(key[..4].try_into().unwrap()));
                self.key[1] = load_u64(&key[4..12]);
                self.key[2] = load_u64(&key[12..]);
            }
        }

        let nonce = params.nonce();
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
    u64::from_be_bytes(input[..8].try_into().unwrap())
}

fn fixed_time_eq(a: &[u8; TAG_BYTES], b: &[u8; TAG_BYTES]) -> bool {
    let mut difference = 0_u8;
    for (&left, &right) in a.iter().zip(b) {
        difference |= left ^ right;
    }
    difference == 0
}
