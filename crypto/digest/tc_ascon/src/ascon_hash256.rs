//! Ascon-Hash256 from NIST SP 800-232.
//!
//! This is the standardized Ascon hash, not the older Ascon v1.2 hash. The
//! NIST version uses little-endian word encoding, an 8-byte rate, the
//! Ascon-p\[12] permutation, and a fixed 256-bit output.

use core::convert::Infallible;

use tc_digest::TryDigest;

use crate::ascon_core::p12;

const DIGEST_LENGTH: usize = 32;
const RATE: usize = 8;
const IV: [u64; 5] = [
    0x9b1e_5494_e934_d681,
    0x4bc3_a01e_3337_51d2,
    0xae65_396c_6b34_b81a,
    0x3c7f_d4a4_d56a_4db3,
    0x1a5c_4649_06c5_976d,
];

/// The standardized 256-bit Ascon hash from NIST SP 800-232.
#[derive(Clone)]
pub struct AsconHash256 {
    state: [u64; 5],
    buffer: [u8; RATE],
    buffer_position: usize,
}

impl Default for AsconHash256 {
    fn default() -> Self {
        Self::new()
    }
}

impl AsconHash256 {
    /// Creates a new Ascon-Hash256 digest.
    pub fn new() -> Self {
        AsconHash256 {
            state: IV,
            buffer: [0; RATE],
            buffer_position: 0,
        }
    }

    #[inline]
    fn absorb_block(&mut self, block: &[u8; RATE]) {
        self.state[0] ^= u64::from_le_bytes(*block);
        p12(&mut self.state);
    }
}

impl TryDigest for AsconHash256 {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        "Ascon-Hash256"
    }

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        RATE
    }

    fn try_update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        if input.is_empty() {
            return Ok(());
        }

        if self.buffer_position != 0 {
            let remaining = RATE - self.buffer_position;
            let copied = remaining.min(input.len());
            self.buffer[self.buffer_position..self.buffer_position + copied]
                .copy_from_slice(&input[..copied]);
            self.buffer_position += copied;
            input = &input[copied..];

            if self.buffer_position == RATE {
                let block = self.buffer;
                self.absorb_block(&block);
                self.buffer_position = 0;
            } else {
                return Ok(());
            }
        }

        while input.len() >= RATE {
            let block: &[u8; RATE] = input[..RATE]
                .try_into()
                .expect("8-byte Ascon-Hash256 block");
            self.absorb_block(block);
            input = &input[RATE..];
        }

        self.buffer[..input.len()].copy_from_slice(input);
        self.buffer_position = input.len();
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let mut final_block = [0u8; RATE];
        final_block[..self.buffer_position].copy_from_slice(&self.buffer[..self.buffer_position]);
        final_block[self.buffer_position] = 0x01;
        self.state[0] ^= u64::from_le_bytes(final_block);
        p12(&mut self.state);

        for (index, chunk) in output[..DIGEST_LENGTH].chunks_exact_mut(RATE).enumerate() {
            if index != 0 {
                p12(&mut self.state);
            }
            chunk.copy_from_slice(&self.state[0].to_le_bytes());
        }

        self.try_reset()?;
        Ok(DIGEST_LENGTH)
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.state = IV;
        self.buffer.fill(0);
        self.buffer_position = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::String, vec::Vec};

    use super::*;
    use tc_digest::Digest;

    fn hex(bytes: &[u8]) -> String {
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            encoded.push_str(&format!("{byte:02x}"));
        }
        encoded
    }

    fn digest_hex(digest: &mut AsconHash256, input: &[u8]) -> String {
        digest.update(input);
        let mut output = [0u8; DIGEST_LENGTH];
        digest.do_final(&mut output);
        hex(&output)
    }

    #[test]
    fn official_ascon_c_kat_vectors() {
        // Selected from ascon-c's NIST SP 800-232 KAT, including rate and
        // long-message boundaries. Each message is 00, 01, ... modulo 256.
        let vectors = [
            (
                0,
                "0b3be5850f2f6b98caf29f8fdea89b64a1fa70aa249b8f839bd53baa304d92b2",
            ),
            (
                1,
                "0728621035af3ed2bca03bf6fde900f9456f5330e4b5ee23e7f6a1e70291bc80",
            ),
            (
                2,
                "6115e7c9c4081c2797fc8fe1bc57a836afa1c5381e556dd583860ca2dfb48dd2",
            ),
            (
                7,
                "3e4d273ba69b3b9c53216107e88b75cdbeedbcbf8faf0219c3928ab62b116577",
            ),
            (
                8,
                "b88e497ae8e6fb641b87ef622eb8f2fca0ed95383f7ffebe167acf1099ba764f",
            ),
            (
                9,
                "94269c30e0296e1ec86655041841823efa1927f520fd58c8e9bce6197878c1a6",
            ),
            (
                15,
                "6421330df99c05eb715415ee17b455f2674f862ae3cc5badffe43a4a3ed273e1",
            ),
            (
                16,
                "3158c1940a2fbadbd68ab661777859b94a689e4efc375911467addd641835c38",
            ),
            (
                17,
                "f149e99dd0f429599bb89b8079bf3f4dca3f298efefcf9b1ea16fe84f9b8b6e2",
            ),
            (
                31,
                "b900cd3f06f1618b68c16665807206dbe273df40135361f449847d573903fabd",
            ),
            (
                32,
                "bd9d3d60a66b53868eab2a5c74539a518a1f60f01eb176c60e43dee81680b33e",
            ),
            (
                33,
                "a58665a2cb9530c502096a7957a76e428af4ad044b4da5c471f9da6f7b3e5868",
            ),
            (
                63,
                "5072896862f6b9cfe8ef76d80559e156254782a40ac5f64cbf7934ad1f624b30",
            ),
            (
                64,
                "a6f241bea5d16405812c06019d9f72d60132bd7c089c60549b2e56bb01c64f48",
            ),
            (
                65,
                "bff4fa006fe6feabb5ce9b219492d0d230f4d05f2bac42db7189f441b1e83b53",
            ),
            (
                126,
                "4666aff6ba886835281152b30fd26f7d8d15c260ed136677c6db21593a476a4e",
            ),
            (
                127,
                "d968938c7f7849403160e291ea54ad79c0caf1237c1375a0b553d5c8122f88b3",
            ),
            (
                128,
                "ce8c1047063527f52dddf77dfa8cff33cad07edd981aae3fe845958209c0ec1f",
            ),
            (
                255,
                "ada496e2c0ade829f37832a8ba34cf6059dffbb3beba88ca5ded3363914ea69a",
            ),
            (
                511,
                "65eb85cf958ab45421a39052dd13e61011dedec9b89c161bd7d1ace2a48a18a9",
            ),
            (
                1024,
                "48140032bb7df2e2b5c95d403c9ab69b4bc00453980bf85f15a84cae2b09a0e9",
            ),
        ];

        let mut digest = AsconHash256::new();
        for (length, expected) in vectors {
            let message: Vec<u8> = (0..length).map(|i| i as u8).collect();
            assert_eq!(
                digest_hex(&mut digest, &message),
                expected,
                "length {length}"
            );

            for chunk in message.chunks(5) {
                digest.update(chunk);
            }
            let mut output = [0u8; DIGEST_LENGTH];
            digest.do_final(&mut output);
            assert_eq!(hex(&output), expected, "chunked length {length}");
        }
    }

    #[test]
    fn accessors_clone_bytewise_and_reset() {
        let message: Vec<u8> = (0..129).map(|i| i as u8).collect();
        let expected = digest_hex(&mut AsconHash256::new(), &message);

        let mut digest = AsconHash256::new();
        assert_eq!(digest.algorithm_name(), "Ascon-Hash256");
        assert_eq!(digest.digest_size(), 32);
        assert_eq!(digest.byte_length(), 8);

        digest.update(&message[..37]);
        let mut cloned = digest.clone();
        digest.update(&message[37..]);
        cloned.update(&message[37..]);
        assert_eq!(digest_hex(&mut digest, b""), expected);
        assert_eq!(digest_hex(&mut cloned, b""), expected);

        for byte in &message {
            digest.update_byte(*byte);
        }
        assert_eq!(digest_hex(&mut digest, b""), expected);

        digest.update(b"discarded state");
        digest.reset();
        digest.update(&message);
        assert_eq!(digest_hex(&mut digest, b""), expected);
    }
}
