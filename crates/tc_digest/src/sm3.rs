//! SM3 message digest, ported from Bouncy Castle's `SM3Digest`.
//!
//! SM3 processes 512-bit blocks into an eight-word state. Its compression
//! function expands 16 input words to 68 words and runs 64 rounds using the
//! `P0`/`P1` permutations and two pairs of boolean functions.

use core::convert::Infallible;

use tc_crypto_core::TryDigest;

use crate::md_buffer::MdBuffer;

const DIGEST_LENGTH: usize = 32;
const BYTE_LENGTH: usize = 64;
const IV: [u32; 8] = [
    0x7380_166f,
    0x4914_b2b9,
    0x1724_42d7,
    0xda8a_0600,
    0xa96f_30bc,
    0x1631_38aa,
    0xe38d_ee4d,
    0xb0fb_0e4e,
];

#[inline(always)]
fn p0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}

#[inline(always)]
fn p1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}

/// Compresses one 512-bit SM3 block.
fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 68];
    for (word, bytes) in w[..16].iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes(bytes.try_into().expect("4-byte SM3 word"));
    }
    for j in 16..68 {
        w[j] = p1(w[j - 16] ^ w[j - 9] ^ w[j - 3].rotate_left(15))
            ^ w[j - 13].rotate_left(7)
            ^ w[j - 6];
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for j in 0..64 {
        let (ff, gg, t) = if j < 16 {
            (a ^ b ^ c, e ^ f ^ g, 0x79cc_4519u32.rotate_left(j as u32))
        } else {
            (
                (a & b) | (a & c) | (b & c),
                (e & f) | ((!e) & g),
                0x7a87_9d8au32.rotate_left((j % 32) as u32),
            )
        };

        let a12 = a.rotate_left(12);
        let ss1 = a12.wrapping_add(e).wrapping_add(t).rotate_left(7);
        let ss2 = ss1 ^ a12;
        let tt1 = ff
            .wrapping_add(d)
            .wrapping_add(ss2)
            .wrapping_add(w[j] ^ w[j + 4]);
        let tt2 = gg.wrapping_add(h).wrapping_add(ss1).wrapping_add(w[j]);

        d = c;
        c = b.rotate_left(9);
        b = a;
        a = tt1;
        h = g;
        g = f.rotate_left(19);
        f = e;
        e = p0(tt2);
    }

    state[0] ^= a;
    state[1] ^= b;
    state[2] ^= c;
    state[3] ^= d;
    state[4] ^= e;
    state[5] ^= f;
    state[6] ^= g;
    state[7] ^= h;
}

/// The 256-bit SM3 message digest.
#[derive(Clone)]
pub struct Sm3Digest {
    state: [u32; 8],
    buf: MdBuffer<64>,
}

impl Default for Sm3Digest {
    fn default() -> Self {
        Sm3Digest {
            state: IV,
            buf: MdBuffer::new(),
        }
    }
}

impl Sm3Digest {
    /// Creates a fresh SM3 digest.
    pub fn new() -> Self {
        Self::default()
    }
}

impl TryDigest for Sm3Digest {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        "SM3"
    }

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        BYTE_LENGTH
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        let Self { state, buf } = self;
        buf.update(input, |block| compress(state, block));
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        {
            let Self { state, buf } = self;
            let bit_length = buf.byte_count() << 3;
            buf.finish(&bit_length.to_be_bytes(), |block| compress(state, block));
            for (i, word) in state.iter().enumerate() {
                output[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
        }
        self.try_reset()?;
        Ok(DIGEST_LENGTH)
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.state = IV;
        self.buf.reset();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::String, vec, vec::Vec};

    use super::*;
    use tc_crypto_core::Digest;

    fn sm3_hex(input: &[u8]) -> String {
        let mut digest = Sm3Digest::new();
        digest.update(input);
        let mut output = [0u8; DIGEST_LENGTH];
        digest.do_final(&mut output);

        let mut encoded = String::with_capacity(DIGEST_LENGTH * 2);
        for byte in output {
            encoded.push_str(&format!("{byte:02x}"));
        }
        encoded
    }

    /// Standard and compact non-standard vectors from BC's `SM3DigestTest`.
    #[test]
    fn known_vectors() {
        let vectors: &[(&[u8], &str)] = &[
            (
                b"abc",
                "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
            ),
            (
                b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
                "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
            ),
            (
                b"",
                "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b",
            ),
            (
                b"a",
                "623476ac18f65a2909e43c7fec61b49c7e764a91a18ccb82f1917a29c86c5e88",
            ),
            (
                b"abcdefghijklmnopqrstuvwxyz",
                "b80fe97a4da24afc277564f66a359ef440462ad28dcc6d63adb24d5c20a61595",
            ),
        ];

        for &(message, expected) in vectors {
            assert_eq!(sm3_hex(message), expected);
        }
    }

    #[test]
    fn long_vectors() {
        let pattern: Vec<u8> = (0..65_536).map(|i| i as u8).collect();
        assert_eq!(
            sm3_hex(&pattern),
            "97049bdc8f0736bc7300eafa9980aeb9cf00f24f7ec3a8f1f8884954d7655c1d"
        );

        let million_a = vec![b'a'; 1_000_000];
        assert_eq!(
            sm3_hex(&million_a),
            "c8aaf89429554029e231941a2acc0ad61ff2a5acd8fadd25847a3a732b3b02c3"
        );
    }

    #[test]
    fn accessors_clone_chunking_and_reset() {
        let message: Vec<u8> = (0..200).map(|i| i as u8).collect();
        let mut whole = Sm3Digest::new();
        assert_eq!(whole.algorithm_name(), "SM3");
        assert_eq!(whole.digest_size(), 32);
        assert_eq!(whole.byte_length(), 64);
        whole.update(&message);

        let mut cloned = whole.clone();
        let mut expected = [0u8; DIGEST_LENGTH];
        let mut cloned_output = [0u8; DIGEST_LENGTH];
        whole.do_final(&mut expected);
        cloned.do_final(&mut cloned_output);
        assert_eq!(cloned_output, expected);

        let mut chunked = Sm3Digest::new();
        chunked.update(&message[..63]);
        chunked.update(&message[63..64]);
        chunked.update(&message[64..]);
        let mut actual = [0u8; DIGEST_LENGTH];
        chunked.do_final(&mut actual);
        assert_eq!(actual, expected);

        chunked.do_final(&mut actual);
        assert_eq!(
            actual,
            [
                0x1a, 0xb2, 0x1d, 0x83, 0x55, 0xcf, 0xa1, 0x7f, 0x8e, 0x61, 0x19, 0x48, 0x31, 0xe8,
                0x1a, 0x8f, 0x22, 0xbe, 0xc8, 0xc7, 0x28, 0xfe, 0xfb, 0x74, 0x7e, 0xd0, 0x35, 0xeb,
                0x50, 0x82, 0xaa, 0x2b,
            ]
        );
    }
}
