//! GOST R 34.11-94 message digest.

use core::convert::Infallible;

use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_digest::TryDigest;
use tc_gost28147::{Gost28147Engine, KeyWithSBox, s_box};

const DIGEST_LENGTH: usize = 32;
const BYTE_LENGTH: usize = 32;

const C2: [u8; 32] = [
    0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00,
    0x00, 0xff, 0xff, 0x00, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0xff,
];

/// The 256-bit GOST R 34.11-94 digest using the CryptoPro D-A S-box.
#[derive(Clone)]
pub struct Gost3411Digest {
    state: [u8; 32],
    checksum: [u8; 32],
    block: [u8; 32],
    block_offset: usize,
    byte_count: u64,
    s_box: [u8; 128],
}

impl Default for Gost3411Digest {
    fn default() -> Self {
        Self::with_s_box(s_box::D_A)
    }
}

impl Gost3411Digest {
    /// Creates a digest using the CryptoPro D-A S-box, matching Bouncy Castle.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a digest using a caller-selected GOST 28147 S-box.
    pub const fn with_s_box(s_box: [u8; 128]) -> Self {
        Self {
            state: [0; 32],
            checksum: [0; 32],
            block: [0; 32],
            block_offset: 0,
            byte_count: 0,
            s_box,
        }
    }

    fn sum_block(&mut self, block: &[u8; 32]) {
        let mut carry = 0u16;
        for (sum, input) in self.checksum.iter_mut().zip(block) {
            carry += *sum as u16 + *input as u16;
            *sum = carry as u8;
            carry >>= 8;
        }
    }

    fn encrypt(&self, key: &[u8; 32], input: &[u8], output: &mut [u8]) {
        let mut cipher = Gost28147Engine::new();
        let params = KeyWithSBox::with_s_box(key, &self.s_box);
        cipher
            .init(CipherDirection::Encrypt, &params)
            .expect("GOST3411 always supplies a 256-bit key and valid S-box");
        cipher
            .process_block(input, output)
            .expect("GOST3411 always supplies full cipher blocks");
    }

    fn process_block(&mut self, message: &[u8; 32]) {
        let mut u = self.state;
        let mut v = *message;
        let mut w = [0u8; 32];
        let mut s = [0u8; 32];

        xor_into(&u, &v, &mut w);
        let key = permute(&w);
        self.encrypt(&key, &self.state[..8], &mut s[..8]);

        for round in 1..4 {
            transform_a(&mut u);
            if round == 2 {
                for (value, constant) in u.iter_mut().zip(C2) {
                    *value ^= constant;
                }
            }
            transform_a(&mut v);
            transform_a(&mut v);
            xor_into(&u, &v, &mut w);
            let key = permute(&w);
            self.encrypt(
                &key,
                &self.state[round * 8..round * 8 + 8],
                &mut s[round * 8..round * 8 + 8],
            );
        }

        for _ in 0..12 {
            transform_fw(&mut s);
        }
        for (value, message) in s.iter_mut().zip(message) {
            *value ^= *message;
        }
        transform_fw(&mut s);
        for (value, state) in s.iter_mut().zip(self.state) {
            *value ^= state;
        }
        for _ in 0..61 {
            transform_fw(&mut s);
        }
        self.state = s;
    }

    fn process_message_block(&mut self, block: &[u8; 32]) {
        self.sum_block(block);
        self.process_block(block);
    }

    fn update_byte_inner(&mut self, byte: u8) {
        self.block[self.block_offset] = byte;
        self.block_offset += 1;
        self.byte_count = self.byte_count.wrapping_add(1);
        if self.block_offset == BYTE_LENGTH {
            let block = self.block;
            self.process_message_block(&block);
            self.block_offset = 0;
        }
    }

    fn finish(&mut self) {
        let bit_count = self.byte_count.wrapping_mul(8);
        while self.block_offset != 0 {
            self.update_byte_inner(0);
        }
        let mut length = [0u8; 32];
        length[..8].copy_from_slice(&bit_count.to_le_bytes());
        self.process_block(&length);
        let checksum = self.checksum;
        self.process_block(&checksum);
    }
}

fn xor_into(left: &[u8; 32], right: &[u8; 32], output: &mut [u8; 32]) {
    for ((output, left), right) in output.iter_mut().zip(left).zip(right) {
        *output = *left ^ *right;
    }
}

fn permute(input: &[u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut offset = 0;
    for column in 0..8 {
        for row in 0..4 {
            output[offset] = input[row * 8 + column];
            offset += 1;
        }
    }
    output
}

fn transform_a(value: &mut [u8; 32]) {
    let mut tail = [0u8; 8];
    for i in 0..8 {
        tail[i] = value[i] ^ value[i + 8];
    }
    value.copy_within(8..32, 0);
    value[24..].copy_from_slice(&tail);
}

fn transform_fw(value: &mut [u8; 32]) {
    let mut words = [0u16; 16];
    for (index, word) in words.iter_mut().enumerate() {
        *word = u16::from_le_bytes([value[index * 2], value[index * 2 + 1]]);
    }
    let feedback = words[0] ^ words[1] ^ words[2] ^ words[3] ^ words[12] ^ words[15];
    words.copy_within(1..16, 0);
    words[15] = feedback;
    for (index, word) in words.iter().enumerate() {
        value[index * 2..index * 2 + 2].copy_from_slice(&word.to_le_bytes());
    }
}

impl TryDigest for Gost3411Digest {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        "Gost3411"
    }

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        BYTE_LENGTH
    }

    fn try_update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        while self.block_offset != 0 && !input.is_empty() {
            self.update_byte_inner(input[0]);
            input = &input[1..];
        }
        while input.len() >= BYTE_LENGTH {
            let block: &[u8; 32] = input[..BYTE_LENGTH].try_into().unwrap();
            self.process_message_block(block);
            self.byte_count = self.byte_count.wrapping_add(BYTE_LENGTH as u64);
            input = &input[BYTE_LENGTH..];
        }
        for &byte in input {
            self.update_byte_inner(byte);
        }
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.finish();
        output[..DIGEST_LENGTH].copy_from_slice(&self.state);
        self.try_reset()?;
        Ok(DIGEST_LENGTH)
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.state = [0; 32];
        self.checksum = [0; 32];
        self.block = [0; 32];
        self.block_offset = 0;
        self.byte_count = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use tc_digest::Digest;

    use super::*;

    fn decode(hex: &str) -> std::vec::Vec<u8> {
        let bytes = hex.as_bytes();
        (0..bytes.len())
            .step_by(2)
            .map(|index| {
                let digit = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => panic!("invalid hex"),
                };
                digit(bytes[index]) << 4 | digit(bytes[index + 1])
            })
            .collect()
    }

    #[test]
    fn bouncy_castle_vectors() {
        let cases = [
            (
                "",
                "981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0",
            ),
            (
                "This is message, length=32 bytes",
                "2cefc2f7b7bdc514e18ea57fa74ff357e7fa17d652c75f69cb1be7893ede48eb",
            ),
            (
                "Suppose the original message has length = 50 bytes",
                "c3730c5cbccacf915ac292676f21e8bd4ef75331d9405e5f1a61dc3130a65011",
            ),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "73b70a39497de53a6e08c67b6d4db853540f03e9389299d9b0156ef7e85d0f61",
            ),
        ];
        for (message, expected) in cases {
            let mut digest = Gost3411Digest::new();
            digest.update(message.as_bytes());
            let mut output = [0u8; 32];
            assert_eq!(digest.do_final(&mut output), 32);
            assert_eq!(output.as_slice(), decode(expected));
        }
    }

    #[test]
    fn caller_selected_d_test_s_box() {
        let mut digest = Gost3411Digest::with_s_box(s_box::D_TEST);
        let mut output = [0u8; 32];
        digest.do_final(&mut output);
        assert_eq!(
            output.as_slice(),
            decode("ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d")
        );
    }

    #[test]
    fn streaming_clone_and_reset() {
        let message = b"Suppose the original message has length = 50 bytes";
        let mut whole = Gost3411Digest::new();
        whole.update(message);
        let mut expected = [0u8; 32];
        whole.do_final(&mut expected);

        let mut chunked = Gost3411Digest::new();
        chunked.update(&message[..17]);
        let mut cloned = chunked.clone();
        chunked.update(&message[17..]);
        cloned.update(&message[17..]);
        let mut actual = [0u8; 32];
        let mut cloned_output = [0u8; 32];
        chunked.do_final(&mut actual);
        cloned.do_final(&mut cloned_output);
        assert_eq!(actual, expected);
        assert_eq!(cloned_output, expected);

        chunked.update(message);
        chunked.do_final(&mut actual);
        assert_eq!(actual, expected);
    }

    #[test]
    fn million_a_vector() {
        let mut digest = Gost3411Digest::new();
        let block = [b'a'; 1000];
        for _ in 0..1000 {
            digest.update(&block);
        }
        let mut output = [0u8; 32];
        digest.do_final(&mut output);
        assert_eq!(
            output.as_slice(),
            decode("8693287aa62f9478f7cb312ec0866b6c4e4a0f11160441e8f4ffcd2715dd554f")
        );
    }
}
