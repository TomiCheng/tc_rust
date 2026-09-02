//! Xoodyak Hash, ported from Bouncy Castle's `XoodyakDigest`.
//!
//! Xoodyak uses the Cyclist mode over the 384-bit Xoodoo permutation. Hashing
//! absorbs at a 16-byte rate and returns a fixed 256-bit digest.

use core::convert::Infallible;

use tc_digest::TryDigest;

const DIGEST_LENGTH: usize = 32;
const ABSORB_RATE: usize = 16;
const SQUEEZE_RATE: usize = 16;

const ROUND_CONSTANTS: [u32; 12] = [
    0x0000_0058,
    0x0000_0038,
    0x0000_03c0,
    0x0000_00d0,
    0x0000_0120,
    0x0000_0014,
    0x0000_0060,
    0x0000_002c,
    0x0000_0380,
    0x0000_00f0,
    0x0000_01a0,
    0x0000_0012,
];

fn xoodoo(state: &mut [u32; 12]) {
    let [
        mut a0,
        mut a1,
        mut a2,
        mut a3,
        mut a4,
        mut a5,
        mut a6,
        mut a7,
        mut a8,
        mut a9,
        mut a10,
        mut a11,
    ] = *state;

    for round_constant in ROUND_CONSTANTS {
        // Theta: column parity mixer.
        let p0 = a0 ^ a4 ^ a8;
        let p1 = a1 ^ a5 ^ a9;
        let p2 = a2 ^ a6 ^ a10;
        let p3 = a3 ^ a7 ^ a11;

        let e0 = p3.rotate_left(5) ^ p3.rotate_left(14);
        let e1 = p0.rotate_left(5) ^ p0.rotate_left(14);
        let e2 = p1.rotate_left(5) ^ p1.rotate_left(14);
        let e3 = p2.rotate_left(5) ^ p2.rotate_left(14);

        a0 ^= e0;
        a4 ^= e0;
        a8 ^= e0;
        a1 ^= e1;
        a5 ^= e1;
        a9 ^= e1;
        a2 ^= e2;
        a6 ^= e2;
        a10 ^= e2;
        a3 ^= e3;
        a7 ^= e3;
        a11 ^= e3;

        // Rho-west and Iota.
        let b0 = a0 ^ round_constant;
        let b1 = a1;
        let b2 = a2;
        let b3 = a3;
        let b4 = a7;
        let b5 = a4;
        let b6 = a5;
        let b7 = a6;
        let mut b8 = a8.rotate_left(11);
        let mut b9 = a9.rotate_left(11);
        let mut b10 = a10.rotate_left(11);
        let mut b11 = a11.rotate_left(11);

        // Chi: nonlinear layer. Temporaries preserve each input plane until
        // all three output planes have been calculated.
        a0 = b0 ^ (!b4 & b8);
        a1 = b1 ^ (!b5 & b9);
        a2 = b2 ^ (!b6 & b10);
        a3 = b3 ^ (!b7 & b11);
        a4 = b4 ^ (!b8 & b0);
        a5 = b5 ^ (!b9 & b1);
        a6 = b6 ^ (!b10 & b2);
        a7 = b7 ^ (!b11 & b3);
        b8 ^= !b0 & b4;
        b9 ^= !b1 & b5;
        b10 ^= !b2 & b6;
        b11 ^= !b3 & b7;

        // Rho-east.
        a4 = a4.rotate_left(1);
        a5 = a5.rotate_left(1);
        a6 = a6.rotate_left(1);
        a7 = a7.rotate_left(1);
        a8 = b10.rotate_left(8);
        a9 = b11.rotate_left(8);
        a10 = b8.rotate_left(8);
        a11 = b9.rotate_left(8);
    }

    *state = [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11];
}

/// The 256-bit Xoodyak Hash digest.
#[derive(Clone)]
pub struct XoodyakDigest {
    state: [u32; 12],
    buffer: [u8; ABSORB_RATE],
    buffer_position: usize,
    updated: bool,
}

impl Default for XoodyakDigest {
    fn default() -> Self {
        Self::new()
    }
}

impl XoodyakDigest {
    /// Creates a new Xoodyak Hash digest.
    pub fn new() -> Self {
        let mut digest = XoodyakDigest {
            state: [0; 12],
            buffer: [0; ABSORB_RATE],
            buffer_position: 0,
            updated: false,
        };
        digest.reset_state();
        digest
    }

    fn reset_state(&mut self) {
        self.state = [0; 12];
        self.buffer.fill(0);
        self.buffer_position = 0;
        self.updated = false;
        // The final byte of the 48-byte state is the Cyclist hash-mode marker.
        self.state[11] ^= 0x0100_0000;
    }

    fn down(&mut self, input: &[u8]) {
        debug_assert!(input.len() <= ABSORB_RATE);
        for (index, byte) in input.iter().copied().enumerate() {
            self.state[index / 4] ^= (byte as u32) << ((index % 4) * 8);
        }
        let delimiter = input.len();
        self.state[delimiter / 4] ^= 1u32 << ((delimiter % 4) * 8);
    }

    #[inline]
    fn up(&mut self) {
        xoodoo(&mut self.state);
    }

    fn absorb_block(&mut self, block: &[u8]) {
        debug_assert_eq!(block.len(), ABSORB_RATE);
        self.down(block);
        self.up();
        self.updated = true;
    }

    fn squeeze(&self, output: &mut [u8]) {
        debug_assert_eq!(output.len(), SQUEEZE_RATE);
        for (word, chunk) in self.state[..4].iter().zip(output.chunks_exact_mut(4)) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
    }
}

impl TryDigest for XoodyakDigest {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        "Xoodyak Hash"
    }

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        ABSORB_RATE
    }

    fn try_update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        if input.is_empty() {
            return Ok(());
        }

        if self.buffer_position != 0 {
            let remaining = ABSORB_RATE - self.buffer_position;
            let copied = remaining.min(input.len());
            self.buffer[self.buffer_position..self.buffer_position + copied]
                .copy_from_slice(&input[..copied]);
            self.buffer_position += copied;
            input = &input[copied..];

            if self.buffer_position == ABSORB_RATE {
                let block = self.buffer;
                self.absorb_block(&block);
                self.buffer_position = 0;
            } else {
                return Ok(());
            }
        }

        while input.len() >= ABSORB_RATE {
            self.absorb_block(&input[..ABSORB_RATE]);
            input = &input[ABSORB_RATE..];
        }

        self.buffer[..input.len()].copy_from_slice(input);
        self.buffer_position = input.len();
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        if self.buffer_position != 0 || !self.updated {
            let position = self.buffer_position;
            let mut final_block = [0u8; ABSORB_RATE];
            final_block[..position].copy_from_slice(&self.buffer[..position]);
            self.down(&final_block[..position]);
            self.up();
        }

        self.squeeze(&mut output[..SQUEEZE_RATE]);
        self.state[0] ^= 1;
        self.up();
        self.squeeze(&mut output[SQUEEZE_RATE..DIGEST_LENGTH]);

        self.reset_state();
        Ok(DIGEST_LENGTH)
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.reset_state();
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

    fn digest_hex(digest: &mut XoodyakDigest, input: &[u8]) -> String {
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
                "ea152f2b47bce24efb66c479d4adf17bd324d806e85ff75ee369ee50dc8f8bd1",
            ),
            (
                1,
                "27921f8ddf392894460b70b3ed6c091e6421b7d2147dcd6031d7efebad3030cc",
            ),
            (
                2,
                "dd3f12e89db41c61d3c05779705fa946a8c69c79eefdc1b4a966a5f1ab35073d",
            ),
            (
                15,
                "db4c9cfe9d385d8ca329e27aeb495a0816c1ab051a57c231a134082661d71bed",
            ),
            (
                16,
                "9ea695347cdddff9bc63ece30fe231441d581768fe223dd6bd7367094fd216b3",
            ),
            (
                17,
                "20593b39bb6d595019331601244411323f713085bb1a30218c972b96d9b7b7b3",
            ),
            (
                31,
                "b91e0c762169748d4e2b8d4972b63a4866caad1b5ebfb7f37deadeb4424df768",
            ),
            (
                32,
                "cebe4aff9eac2218017dda5f8207ba830e989187256539bd7d31ae5e94ff0c6e",
            ),
            (
                33,
                "249cfccd50d66e722e80e79002ce3b302b4ca067483ab9cdeb474dbf555b7633",
            ),
            (
                63,
                "2e9edd78f51e549df9d0fced6a98cfec3a78bd3957772c30d9a7c6f0a2dccba7",
            ),
            (
                64,
                "68a2e4b661525133dec09d918b61e40d38cdd0e59638b5a9709ab2a4af2d8f13",
            ),
            (
                65,
                "3bdc2064815298a08eb28ceb90ef123b2c1a24350d6907dfae71b07e40304404",
            ),
            (
                127,
                "c12a09953dc8079bc0a83ad549e5039516ca6f8185d604f121057292502c9a25",
            ),
            (
                128,
                "3f06099548d9202d436488cf46eb551e4746c7cf04cee7b0c2d53c05ac5c73ca",
            ),
            (
                255,
                "0a4d8c6949c3231218716af56e76425a1b6477a3234e51f52abe6a82a0cca551",
            ),
            (
                511,
                "a7bae8e388a9c548cdbc9e323926fa3291211f8d1256c60c75de84e6f69f1dac",
            ),
            (
                1024,
                "fcc4d63932d98c30cab597e60b7cca475bd9fbf984838c5cb5615c949f814615",
            ),
        ];

        let mut digest = XoodyakDigest::new();
        for (length, expected) in vectors {
            let message: Vec<u8> = (0..length).map(|i| i as u8).collect();
            assert_eq!(
                digest_hex(&mut digest, &message),
                expected,
                "length {length}"
            );

            for chunk in message.chunks(7) {
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
        let expected = digest_hex(&mut XoodyakDigest::new(), &message);

        let mut digest = XoodyakDigest::new();
        assert_eq!(digest.algorithm_name(), "Xoodyak Hash");
        assert_eq!(digest.digest_size(), 32);
        assert_eq!(digest.byte_length(), 16);

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
