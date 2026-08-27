//! ISAP Hash, ported from Bouncy Castle's `IsapDigest`.
//!
//! ISAP Hash is the fixed-output hashing component of the ISAP lightweight
//! authenticated-encryption family. It absorbs at an 8-byte rate into a
//! 320-bit state and applies the 12-round ISAP permutation between blocks.

use core::convert::Infallible;

use tc_crypto_core::TryDigest;

use crate::ascon_core::p12;

const DIGEST_LENGTH: usize = 32;
const BYTE_LENGTH: usize = 8;
const IV: [u64; 5] = [
    0xee93_98aa_db67_f03d,
    0x8bb2_1831_c60f_1002,
    0xb48a_92db_98d5_da62,
    0x4318_9921_b8f8_e3e8,
    0x348f_a5c9_d525_e140,
];

/// The 256-bit ISAP Hash digest.
#[derive(Clone)]
pub struct IsapDigest {
    state: [u64; 5],
    buffer: [u8; BYTE_LENGTH],
    buffer_position: usize,
}

impl Default for IsapDigest {
    fn default() -> Self {
        Self::new()
    }
}

impl IsapDigest {
    /// Creates a new ISAP Hash digest.
    pub fn new() -> Self {
        IsapDigest {
            state: IV,
            buffer: [0; BYTE_LENGTH],
            buffer_position: 0,
        }
    }

    #[inline]
    fn absorb_block(&mut self, block: &[u8; BYTE_LENGTH]) {
        self.state[0] ^= u64::from_be_bytes(*block);
        p12(&mut self.state);
    }
}

impl TryDigest for IsapDigest {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        "ISAP Hash"
    }

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        BYTE_LENGTH
    }

    fn try_update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        if input.is_empty() {
            return Ok(());
        }

        if self.buffer_position != 0 {
            let remaining = BYTE_LENGTH - self.buffer_position;
            let copied = remaining.min(input.len());
            self.buffer[self.buffer_position..self.buffer_position + copied]
                .copy_from_slice(&input[..copied]);
            self.buffer_position += copied;
            input = &input[copied..];

            if self.buffer_position == BYTE_LENGTH {
                let block = self.buffer;
                self.absorb_block(&block);
                self.buffer_position = 0;
            } else {
                return Ok(());
            }
        }

        while input.len() >= BYTE_LENGTH {
            let block: &[u8; BYTE_LENGTH] = input[..BYTE_LENGTH]
                .try_into()
                .expect("8-byte ISAP Hash block");
            self.absorb_block(block);
            input = &input[BYTE_LENGTH..];
        }

        self.buffer[..input.len()].copy_from_slice(input);
        self.buffer_position = input.len();
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let mut final_block = [0u8; BYTE_LENGTH];
        final_block[..self.buffer_position].copy_from_slice(&self.buffer[..self.buffer_position]);
        final_block[self.buffer_position] = 0x80;
        self.state[0] ^= u64::from_be_bytes(final_block);

        for chunk in output[..DIGEST_LENGTH].chunks_exact_mut(BYTE_LENGTH) {
            p12(&mut self.state);
            chunk.copy_from_slice(&self.state[0].to_be_bytes());
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
    use tc_crypto_core::Digest;

    fn hex(bytes: &[u8]) -> String {
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            encoded.push_str(&format!("{byte:02x}"));
        }
        encoded
    }

    fn digest_hex(digest: &mut IsapDigest, input: &[u8]) -> String {
        digest.update(input);
        let mut output = [0u8; DIGEST_LENGTH];
        digest.do_final(&mut output);
        hex(&output)
    }

    #[test]
    fn nist_lwc_kat_vectors() {
        // Selected from the official LWC_HASH_KAT_256 set, including rate and
        // long-message boundaries. Each message is 00, 01, ... modulo 256.
        let vectors = [
            (
                0,
                "7346bc14f036e87ae03d0997913088f5f68411434b3cf8b54fa796a80d251f91",
            ),
            (
                1,
                "8dd446ada58a7740ecf56eb638ef775f7d5c0fd5f0c2bbbdfdec29609d3c43a2",
            ),
            (
                2,
                "f77ca13bf89146d3254f1cfb7eddba8fa1bf162284bb29e7f645545cf9e08424",
            ),
            (
                7,
                "dd409ccc0c60cd7f474c0beed1e1cd48140ad45d5136dc5fda5ebe283df8d3f6",
            ),
            (
                8,
                "f4c6a44b29915d3d57cf928a18ec6226bb8dd6c1136acd24965f7e7780cd69cf",
            ),
            (
                9,
                "1e1e710d08a78263773331782621088ca9fe2ee4f596f06c8f7884ca564acec1",
            ),
            (
                63,
                "8dcedc0ac6b37defc36f0b1afa281d31437658a8ffa7b4a569ea9988a9efd7f5",
            ),
            (
                64,
                "5179e733b8a84f4c8a6898043c09f6a779bd6811d21aa25d353e357048279862",
            ),
            (
                65,
                "21dbd0777a9ee81bebe465570bcdb9ecaed6073b5eb69f2831864c4956aa6a15",
            ),
            (
                126,
                "462efa7523f645211162272fb416a5d69da3e0f934f9e8277508da6d6046cbb4",
            ),
            (
                127,
                "0f75dc9132ff23f25b2335ed9a16e68af5ec1df385c41a4c8a471a6ae6cb1beb",
            ),
            (
                128,
                "99f85ae900901d2667fe7fbc52ab6a924fd4aa902bc03019c92106f83578d459",
            ),
            (
                255,
                "d4d7b2b70bd7f57c37be24c5f9d14207b737d8c21632b1ae3093b7a740cddd3e",
            ),
            (
                511,
                "be78f06ce088606fdd0b3a7143ad19436bf6867457e2a1559ea9a477978e121f",
            ),
            (
                1024,
                "2eb89744de7f9a6f47d53db756bb2f67b127da96762a1c47a5d7bfc1f7273f5c",
            ),
        ];

        let mut digest = IsapDigest::new();
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
        let expected = digest_hex(&mut IsapDigest::new(), &message);

        let mut digest = IsapDigest::new();
        assert_eq!(digest.algorithm_name(), "ISAP Hash");
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
