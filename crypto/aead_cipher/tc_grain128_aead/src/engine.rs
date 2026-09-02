//! Incremental Grain-128AEAD engine.

use tc_cipher::{AeadCipher, AeadCipherInit, AeadError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::{AadLengthParams, InitialAadParams, IvParams, KeyParams};

use crate::{KEY_BYTES, NONCE_BYTES, TAG_BYTES};

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

/// Allocation-free incremental Grain-128AEAD engine.
///
/// Grain-128AEAD uses a 16-byte key, a 12-byte nonce, and an 8-byte tag. Its
/// AAD length must be declared through [`AadLengthParams::aad_len`] during
/// initialization so the engine can encode that length before streaming AAD.
///
/// Decryption may emit unauthenticated plaintext before
/// [`AeadCipher::do_final`] verifies the tag. Callers must not release that
/// plaintext before finalization succeeds.
pub struct Engine {
    key: [u8; KEY_BYTES],
    nonce: [u8; NONCE_BYTES],
    lfsr: [u32; 4],
    nfsr: [u32; 4],
    auth: [u32; 4],
    tag_buffer: [u8; TAG_BYTES],
    tag_buffer_pos: usize,
    aad_expected: usize,
    aad_processed: usize,
    state: State,
    mac: Option<[u8; TAG_BYTES]>,
}

impl Engine {
    /// Creates an uninitialised Grain-128AEAD engine.
    pub const fn new() -> Self {
        Self {
            key: [0; KEY_BYTES],
            nonce: [0; NONCE_BYTES],
            lfsr: [0; 4],
            nfsr: [0; 4],
            auth: [0; 4],
            tag_buffer: [0; TAG_BYTES],
            tag_buffer_pos: 0,
            aad_expected: 0,
            aad_processed: 0,
            state: State::Uninitialised,
            mac: None,
        }
    }

    /// Returns the required key length in bytes.
    pub const fn key_bytes(&self) -> usize {
        KEY_BYTES
    }

    /// Returns the required nonce length in bytes.
    pub const fn nonce_bytes(&self) -> usize {
        NONCE_BYTES
    }

    /// Returns the authentication-tag length in bytes.
    pub const fn tag_bytes(&self) -> usize {
        TAG_BYTES
    }

    fn check_aad(&mut self) -> Result<(), AeadError> {
        self.state = match self.state {
            State::EncryptInit => State::EncryptAad,
            State::DecryptInit => State::DecryptAad,
            State::EncryptAad | State::DecryptAad => self.state,
            State::EncryptData | State::DecryptData => {
                return Err(AeadError::AadAfterData);
            }
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
        if self.aad_processed != self.aad_expected {
            return Err(AeadError::AadLengthMismatch {
                expected: self.aad_expected,
                actual: self.aad_processed,
            });
        }

        self.state = match self.state {
            State::EncryptInit | State::EncryptAad => State::EncryptData,
            State::DecryptInit | State::DecryptAad => State::DecryptData,
            State::EncryptData | State::DecryptData => self.state,
            State::EncryptFinal | State::DecryptFinal => {
                return Err(AeadError::AlreadyFinalised);
            }
            State::Uninitialised => return Err(AeadError::NotInitialised),
        };
        self.current_direction()
    }

    fn initialise_grain(&mut self) {
        for (word, bytes) in self.nfsr.iter_mut().zip(self.key.chunks_exact(4)) {
            *word = u32::from_le_bytes(bytes.try_into().unwrap());
        }
        for (word, bytes) in self.lfsr[..3].iter_mut().zip(self.nonce.chunks_exact(4)) {
            *word = u32::from_le_bytes(bytes.try_into().unwrap());
        }
        self.lfsr[3] = 0x7fff_ffff;

        for _ in 0..320 {
            let output = self.output();
            self.shift_state(output, output);
        }
        for byte_index in 0..8 {
            let key_low = self.key[byte_index];
            let key_high = self.key[byte_index + 8];
            for bit_index in 0..8 {
                let output = self.output();
                let low_bit = u32::from((key_low >> bit_index) & 1);
                let high_bit = u32::from((key_high >> bit_index) & 1);
                self.shift_state(output ^ low_bit, output ^ high_bit);
            }
        }
        for word_index in 0..self.auth.len() {
            let mut value = 0_u32;
            for bit_index in 0..32 {
                let output = self.output();
                self.shift_state(0, 0);
                value |= output << bit_index;
            }
            self.auth[word_index] = value;
        }
    }

    fn process_aad_length(&mut self, aad_len: usize) {
        let mut encoding = [0_u8; 1 + size_of::<usize>()];
        let encoded = if aad_len < 128 {
            encoding[0] = aad_len as u8;
            &encoding[..1]
        } else {
            let bytes = aad_len.to_be_bytes();
            let first = bytes.iter().position(|&byte| byte != 0).unwrap();
            let count = bytes.len() - first;
            encoding[0] = 0x80 | count as u8;
            encoding[1..1 + count].copy_from_slice(&bytes[first..]);
            &encoding[..1 + count]
        };

        for &byte in encoded {
            self.process_aad_byte(byte);
        }
    }

    fn process_aad_byte(&mut self, byte: u8) {
        for bit_index in 0..8 {
            self.shift_state(0, 0);
            let bit = u32::from((byte >> bit_index) & 1);
            let mask = 0_u32.wrapping_sub(bit);
            self.auth[0] ^= self.auth[2] & mask;
            self.auth[1] ^= self.auth[3] & mask;
            let output = self.output();
            self.shift_auth(output);
            self.shift_state(0, 0);
        }
    }

    fn process_data_byte(&mut self, input: u8, encrypt: bool) -> u8 {
        let mut output_byte = 0_u8;
        for bit_index in 0..8 {
            let input_bit = u32::from((input >> bit_index) & 1);
            let stream_bit = self.output();
            let plaintext_bit = if encrypt {
                input_bit
            } else {
                input_bit ^ stream_bit
            };
            let result_bit = if encrypt {
                plaintext_bit ^ stream_bit
            } else {
                plaintext_bit
            };
            self.shift_state(0, 0);
            output_byte |= (result_bit as u8) << bit_index;

            let mask = 0_u32.wrapping_sub(plaintext_bit);
            self.auth[0] ^= self.auth[2] & mask;
            self.auth[1] ^= self.auth[3] & mask;
            let output = self.output();
            self.shift_auth(output);
            self.shift_state(0, 0);
        }
        output_byte
    }

    fn finish_data(&mut self) -> [u8; TAG_BYTES] {
        self.auth[0] ^= self.auth[2];
        self.auth[1] ^= self.auth[3];
        let mut tag = [0_u8; TAG_BYTES];
        tag[..4].copy_from_slice(&self.auth[0].to_le_bytes());
        tag[4..].copy_from_slice(&self.auth[1].to_le_bytes());
        tag
    }

    fn output(&self) -> u32 {
        let b2 = self.nfsr[0] >> 2;
        let b12 = self.nfsr[0] >> 12;
        let b15 = self.nfsr[0] >> 15;
        let b36 = self.nfsr[1] >> 4;
        let b45 = self.nfsr[1] >> 13;
        let b64 = self.nfsr[2];
        let b73 = self.nfsr[2] >> 9;
        let b89 = self.nfsr[2] >> 25;
        let b95 = self.nfsr[2] >> 31;
        let s8 = self.lfsr[0] >> 8;
        let s13 = self.lfsr[0] >> 13;
        let s20 = self.lfsr[0] >> 20;
        let s42 = self.lfsr[1] >> 10;
        let s60 = self.lfsr[1] >> 28;
        let s79 = self.lfsr[2] >> 15;
        let s93 = self.lfsr[2] >> 29;
        let s94 = self.lfsr[2] >> 30;

        ((b12 & s8)
            ^ (s13 & s20)
            ^ (b95 & s42)
            ^ (s60 & s79)
            ^ (b12 & b95 & s94)
            ^ s93
            ^ b2
            ^ b15
            ^ b36
            ^ b45
            ^ b64
            ^ b73
            ^ b89)
            & 1
    }

    fn lfsr_output(&self) -> u32 {
        self.lfsr[0]
            ^ (self.lfsr[0] >> 7)
            ^ (self.lfsr[1] >> 6)
            ^ (self.lfsr[2] >> 6)
            ^ (self.lfsr[2] >> 17)
            ^ self.lfsr[3]
    }

    fn nfsr_output(&self) -> u32 {
        let b0 = self.nfsr[0];
        let b3 = self.nfsr[0] >> 3;
        let b11 = self.nfsr[0] >> 11;
        let b13 = self.nfsr[0] >> 13;
        let b17 = self.nfsr[0] >> 17;
        let b18 = self.nfsr[0] >> 18;
        let b22 = self.nfsr[0] >> 22;
        let b24 = self.nfsr[0] >> 24;
        let b25 = self.nfsr[0] >> 25;
        let b26 = self.nfsr[0] >> 26;
        let b27 = self.nfsr[0] >> 27;
        let b40 = self.nfsr[1] >> 8;
        let b48 = self.nfsr[1] >> 16;
        let b56 = self.nfsr[1] >> 24;
        let b59 = self.nfsr[1] >> 27;
        let b61 = self.nfsr[1] >> 29;
        let b65 = self.nfsr[2] >> 1;
        let b67 = self.nfsr[2] >> 3;
        let b68 = self.nfsr[2] >> 4;
        let b70 = self.nfsr[2] >> 6;
        let b78 = self.nfsr[2] >> 14;
        let b82 = self.nfsr[2] >> 18;
        let b84 = self.nfsr[2] >> 20;
        let b88 = self.nfsr[2] >> 24;
        let b91 = self.nfsr[2] >> 27;
        let b92 = self.nfsr[2] >> 28;
        let b93 = self.nfsr[2] >> 29;
        let b95 = self.nfsr[2] >> 31;
        let b96 = self.nfsr[3];

        b0 ^ b26
            ^ b56
            ^ b91
            ^ b96
            ^ (b3 & b67)
            ^ (b11 & b13)
            ^ (b17 & b18)
            ^ (b27 & b59)
            ^ (b40 & b48)
            ^ (b61 & b65)
            ^ (b68 & b84)
            ^ (b22 & b24 & b25)
            ^ (b70 & b78 & b82)
            ^ (b88 & b92 & b93 & b95)
    }

    fn shift_state(&mut self, nfsr_extra: u32, lfsr_extra: u32) {
        let nfsr_bit = self.nfsr_output() ^ self.lfsr[0] ^ nfsr_extra;
        let lfsr_bit = self.lfsr_output() ^ lfsr_extra;
        shift_bit(&mut self.nfsr, nfsr_bit);
        shift_bit(&mut self.lfsr, lfsr_bit);
    }

    fn shift_auth(&mut self, value: u32) {
        self.auth[2] = (self.auth[2] >> 1) | (self.auth[3] << 31);
        self.auth[3] = (self.auth[3] >> 1) | (value << 31);
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for Engine {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        output.write_str("Grain-128AEAD")
    }
}

impl AeadCipher for Engine {
    type Error = AeadError;

    fn process_aad_bytes(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        if input.is_empty() {
            return Ok(());
        }
        self.check_aad()?;
        let new_total = self.aad_processed.saturating_add(input.len());
        if new_total > self.aad_expected {
            return Err(AeadError::AadLengthMismatch {
                expected: self.aad_expected,
                actual: new_total,
            });
        }

        self.mac = None;
        for &byte in input {
            self.process_aad_byte(byte);
        }
        self.aad_processed = new_total;
        Ok(())
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let direction = self.current_direction()?;
        let required = self.get_update_output_size(input.len());
        if output.len() < required {
            return Err(AeadError::OutputTooShort {
                required,
                available: output.len(),
            });
        }
        debug_assert_eq!(self.start_data()?, direction);
        self.mac = None;

        match direction {
            CipherDirection::Encrypt => {
                for (&input, output) in input.iter().zip(output.iter_mut()) {
                    *output = self.process_data_byte(input, true);
                }
                Ok(input.len())
            }
            CipherDirection::Decrypt => {
                let mut written = 0;
                for &byte in input {
                    if self.tag_buffer_pos < TAG_BYTES {
                        self.tag_buffer[self.tag_buffer_pos] = byte;
                        self.tag_buffer_pos += 1;
                    } else {
                        output[written] = self.process_data_byte(self.tag_buffer[0], false);
                        written += 1;
                        self.tag_buffer.copy_within(1.., 0);
                        self.tag_buffer[TAG_BYTES - 1] = byte;
                    }
                }
                Ok(written)
            }
        }
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let direction = self.current_direction()?;
        let required = self.get_output_size(0);
        if output.len() < required {
            return Err(AeadError::OutputTooShort {
                required,
                available: output.len(),
            });
        }
        if direction == CipherDirection::Decrypt && self.tag_buffer_pos < TAG_BYTES {
            self.mac = None;
            return Err(AeadError::CiphertextTooShort {
                minimum: TAG_BYTES,
                actual: self.tag_buffer_pos,
            });
        }
        debug_assert_eq!(self.start_data()?, direction);
        self.mac = None;
        let expected_tag = self.finish_data();

        match direction {
            CipherDirection::Encrypt => {
                output[..TAG_BYTES].copy_from_slice(&expected_tag);
                self.mac = Some(expected_tag);
                self.state = State::EncryptFinal;
                Ok(TAG_BYTES)
            }
            CipherDirection::Decrypt => {
                let received_tag = self.tag_buffer;
                self.tag_buffer.fill(0);
                self.tag_buffer_pos = 0;
                self.state = State::DecryptFinal;
                if !fixed_time_eq(&expected_tag, &received_tag) {
                    return Err(AeadError::AuthenticationFailed);
                }
                self.mac = Some(received_tag);
                Ok(0)
            }
        }
    }

    fn mac(&self) -> Option<&[u8]> {
        self.mac.as_ref().map(|mac| mac.as_slice())
    }

    fn get_update_output_size(&self, input_len: usize) -> usize {
        match self.state {
            State::DecryptInit | State::DecryptAad => input_len.saturating_sub(TAG_BYTES),
            State::DecryptData | State::DecryptFinal => self
                .tag_buffer_pos
                .saturating_add(input_len)
                .saturating_sub(TAG_BYTES),
            _ => input_len,
        }
    }

    fn get_output_size(&self, input_len: usize) -> usize {
        match self.state {
            State::DecryptInit | State::DecryptAad => input_len.saturating_sub(TAG_BYTES),
            State::DecryptData | State::DecryptFinal => self
                .tag_buffer_pos
                .saturating_add(input_len)
                .saturating_sub(TAG_BYTES),
            _ => input_len.saturating_add(TAG_BYTES),
        }
    }
}

impl<P> AeadCipherInit<P> for Engine
where
    P: KeyParams + IvParams + InitialAadParams + AadLengthParams + ?Sized,
{
    type Error = InitError;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.state = State::Uninitialised;
        self.mac = None;
        self.key.fill(0);
        self.nonce.fill(0);
        self.lfsr.fill(0);
        self.nfsr.fill(0);
        self.auth.fill(0);
        self.tag_buffer.fill(0);
        self.tag_buffer_pos = 0;
        self.aad_expected = 0;
        self.aad_processed = 0;

        let key = params.key();
        if key.len() != KEY_BYTES {
            return Err(InitError::InvalidKeyLength(key.len()));
        }
        let nonce = params.iv();
        if nonce.len() != NONCE_BYTES {
            return Err(InitError::InvalidIvLength(nonce.len()));
        }
        let initial_aad = params.initial_aad();
        let aad_len = params.aad_len();
        if initial_aad.len() > aad_len {
            return Err(InitError::InvalidAadLength {
                expected: aad_len,
                actual: initial_aad.len(),
            });
        }

        self.key.copy_from_slice(key);
        self.nonce.copy_from_slice(nonce);
        self.lfsr.fill(0);
        self.nfsr.fill(0);
        self.auth.fill(0);
        self.tag_buffer.fill(0);
        self.tag_buffer_pos = 0;
        self.aad_expected = aad_len;
        self.aad_processed = 0;
        self.mac = None;
        self.state = match direction {
            CipherDirection::Encrypt => State::EncryptInit,
            CipherDirection::Decrypt => State::DecryptInit,
        };
        self.initialise_grain();
        self.process_aad_length(aad_len);
        if !initial_aad.is_empty() {
            self.state = match direction {
                CipherDirection::Encrypt => State::EncryptAad,
                CipherDirection::Decrypt => State::DecryptAad,
            };
            for &byte in initial_aad {
                self.process_aad_byte(byte);
            }
            self.aad_processed = initial_aad.len();
        }
        Ok(())
    }
}

fn shift_bit(words: &mut [u32; 4], value: u32) {
    words[0] = (words[0] >> 1) | (words[1] << 31);
    words[1] = (words[1] >> 1) | (words[2] << 31);
    words[2] = (words[2] >> 1) | (words[3] << 31);
    words[3] = (words[3] >> 1) | (value << 31);
}

fn fixed_time_eq(left: &[u8; TAG_BYTES], right: &[u8; TAG_BYTES]) -> bool {
    let mut difference = 0_u8;
    for (&left, &right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}
