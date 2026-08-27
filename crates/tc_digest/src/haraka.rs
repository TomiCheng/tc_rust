//! Haraka-256/256 and Haraka-512/256, ported from Bouncy Castle.
//!
//! Haraka is a short-input hash built from reduced-round AES permutations. These
//! two variants accept exactly 32 and 64 bytes respectively and both produce a
//! 32-byte digest. The portable AES round is always available; with `std` on
//! x86/x86-64, AES-NI is selected at runtime when supported.

use core::fmt;

use tc_crypto_core::TryDigest;

const DIGEST_LENGTH: usize = 32;
type Block = [u8; 16];

// Haraka v2 round constants, in the byte order used by the AES round.
const ROUND_CONSTANTS: [Block; 40] = [
    [
        0x9d, 0x7b, 0x81, 0x75, 0xf0, 0xfe, 0xc5, 0xb2, 0x0a, 0xc0, 0x20, 0xe6, 0x4c, 0x70, 0x84,
        0x06,
    ],
    [
        0x17, 0xf7, 0x08, 0x2f, 0xa4, 0x6b, 0x0f, 0x64, 0x6b, 0xa0, 0xf3, 0x88, 0xe1, 0xb4, 0x66,
        0x8b,
    ],
    [
        0x14, 0x91, 0x02, 0x9f, 0x60, 0x9d, 0x02, 0xcf, 0x98, 0x84, 0xf2, 0x53, 0x2d, 0xde, 0x02,
        0x34,
    ],
    [
        0x79, 0x4f, 0x5b, 0xfd, 0xaf, 0xbc, 0xf3, 0xbb, 0x08, 0x4f, 0x7b, 0x2e, 0xe6, 0xea, 0xd6,
        0x0e,
    ],
    [
        0x44, 0x70, 0x39, 0xbe, 0x1c, 0xcd, 0xee, 0x79, 0x8b, 0x44, 0x72, 0x48, 0xcb, 0xb0, 0xcf,
        0xcb,
    ],
    [
        0x7b, 0x05, 0x8a, 0x2b, 0xed, 0x35, 0x53, 0x8d, 0xb7, 0x32, 0x90, 0x6e, 0xee, 0xcd, 0xea,
        0x7e,
    ],
    [
        0x1b, 0xef, 0x4f, 0xda, 0x61, 0x27, 0x41, 0xe2, 0xd0, 0x7c, 0x2e, 0x5e, 0x43, 0x8f, 0xc2,
        0x67,
    ],
    [
        0x3b, 0x0b, 0xc7, 0x1f, 0xe2, 0xfd, 0x5f, 0x67, 0x07, 0xcc, 0xca, 0xaf, 0xb0, 0xd9, 0x24,
        0x29,
    ],
    [
        0xee, 0x65, 0xd4, 0xb9, 0xca, 0x8f, 0xdb, 0xec, 0xe9, 0x7f, 0x86, 0xe6, 0xf1, 0x63, 0x4d,
        0xab,
    ],
    [
        0x33, 0x7e, 0x03, 0xad, 0x4f, 0x40, 0x2a, 0x5b, 0x64, 0xcd, 0xb7, 0xd4, 0x84, 0xbf, 0x30,
        0x1c,
    ],
    [
        0x00, 0x98, 0xf6, 0x8d, 0x2e, 0x8b, 0x02, 0x69, 0xbf, 0x23, 0x17, 0x94, 0xb9, 0x0b, 0xcc,
        0xb2,
    ],
    [
        0x8a, 0x2d, 0x9d, 0x5c, 0xc8, 0x9e, 0xaa, 0x4a, 0x72, 0x55, 0x6f, 0xde, 0xa6, 0x78, 0x04,
        0xfa,
    ],
    [
        0xd4, 0x9f, 0x12, 0x29, 0x2e, 0x4f, 0xfa, 0x0e, 0x12, 0x2a, 0x77, 0x6b, 0x2b, 0x9f, 0xb4,
        0xdf,
    ],
    [
        0xee, 0x12, 0x6a, 0xbb, 0xae, 0x11, 0xd6, 0x32, 0x36, 0xa2, 0x49, 0xf4, 0x44, 0x03, 0xa1,
        0x1e,
    ],
    [
        0xa6, 0xec, 0xa8, 0x9c, 0xc9, 0x00, 0x96, 0x5f, 0x84, 0x00, 0x05, 0x4b, 0x88, 0x49, 0x04,
        0xaf,
    ],
    [
        0xec, 0x93, 0xe5, 0x27, 0xe3, 0xc7, 0xa2, 0x78, 0x4f, 0x9c, 0x19, 0x9d, 0xd8, 0x5e, 0x02,
        0x21,
    ],
    [
        0x73, 0x01, 0xd4, 0x82, 0xcd, 0x2e, 0x28, 0xb9, 0xb7, 0xc9, 0x59, 0xa7, 0xf8, 0xaa, 0x3a,
        0xbf,
    ],
    [
        0x6b, 0x7d, 0x30, 0x10, 0xd9, 0xef, 0xf2, 0x37, 0x17, 0xb0, 0x86, 0x61, 0x0d, 0x70, 0x60,
        0x62,
    ],
    [
        0xc6, 0x9a, 0xfc, 0xf6, 0x53, 0x91, 0xc2, 0x81, 0x43, 0x04, 0x30, 0x21, 0xc2, 0x45, 0xca,
        0x5a,
    ],
    [
        0x3a, 0x94, 0xd1, 0x36, 0xe8, 0x92, 0xaf, 0x2c, 0xbb, 0x68, 0x6b, 0x22, 0x3c, 0x97, 0x23,
        0x92,
    ],
    [
        0xb4, 0x71, 0x10, 0xe5, 0x58, 0xb9, 0xba, 0x6c, 0xeb, 0x86, 0x58, 0x22, 0x38, 0x92, 0xbf,
        0xd3,
    ],
    [
        0x8d, 0x12, 0xe1, 0x24, 0xdd, 0xfd, 0x3d, 0x93, 0x77, 0xc6, 0xf0, 0xae, 0xe5, 0x3c, 0x86,
        0xdb,
    ],
    [
        0xb1, 0x12, 0x22, 0xcb, 0xe3, 0x8d, 0xe4, 0x83, 0x9c, 0xa0, 0xeb, 0xff, 0x68, 0x62, 0x60,
        0xbb,
    ],
    [
        0x7d, 0xf7, 0x2b, 0xc7, 0x4e, 0x1a, 0xb9, 0x2d, 0x9c, 0xd1, 0xe4, 0xe2, 0xdc, 0xd3, 0x4b,
        0x73,
    ],
    [
        0x4e, 0x92, 0xb3, 0x2c, 0xc4, 0x15, 0x14, 0x4b, 0x43, 0x1b, 0x30, 0x61, 0xc3, 0x47, 0xbb,
        0x43,
    ],
    [
        0x99, 0x68, 0xeb, 0x16, 0xdd, 0x31, 0xb2, 0x03, 0xf6, 0xef, 0x07, 0xe7, 0xa8, 0x75, 0xa7,
        0xdb,
    ],
    [
        0x2c, 0x47, 0xca, 0x7e, 0x02, 0x23, 0x5e, 0x8e, 0x77, 0x59, 0x75, 0x3c, 0x4b, 0x61, 0xf3,
        0x6d,
    ],
    [
        0xf9, 0x17, 0x86, 0xb8, 0xb9, 0xe5, 0x1b, 0x6d, 0x77, 0x7d, 0xde, 0xd6, 0x17, 0x5a, 0xa7,
        0xcd,
    ],
    [
        0x5d, 0xee, 0x46, 0xa9, 0x9d, 0x06, 0x6c, 0x9d, 0xaa, 0xe9, 0xa8, 0x6b, 0xf0, 0x43, 0x6b,
        0xec,
    ],
    [
        0xc1, 0x27, 0xf3, 0x3b, 0x59, 0x11, 0x53, 0xa2, 0x2b, 0x33, 0x57, 0xf9, 0x50, 0x69, 0x1e,
        0xcb,
    ],
    [
        0xd9, 0xd0, 0x0e, 0x60, 0x53, 0x03, 0xed, 0xe4, 0x9c, 0x61, 0xda, 0x00, 0x75, 0x0c, 0xee,
        0x2c,
    ],
    [
        0x50, 0xa3, 0xa4, 0x63, 0xbc, 0xba, 0xbb, 0x80, 0xab, 0x0c, 0xe9, 0x96, 0xa1, 0xa5, 0xb1,
        0xf0,
    ],
    [
        0x39, 0xca, 0x8d, 0x93, 0x30, 0xde, 0x0d, 0xab, 0x88, 0x29, 0x96, 0x5e, 0x02, 0xb1, 0x3d,
        0xae,
    ],
    [
        0x42, 0xb4, 0x75, 0x2e, 0xa8, 0xf3, 0x14, 0x88, 0x0b, 0xa4, 0x54, 0xd5, 0x38, 0x8f, 0xbb,
        0x17,
    ],
    [
        0xf6, 0x16, 0x0a, 0x36, 0x79, 0xb7, 0xb6, 0xae, 0xd7, 0x7f, 0x42, 0x5f, 0x5b, 0x8a, 0xbb,
        0x34,
    ],
    [
        0xde, 0xaf, 0xba, 0xff, 0x18, 0x59, 0xce, 0x43, 0x38, 0x54, 0xe5, 0xcb, 0x41, 0x52, 0xf6,
        0x26,
    ],
    [
        0x78, 0xc9, 0x9e, 0x83, 0xf7, 0x9c, 0xca, 0xa2, 0x6a, 0x02, 0xf3, 0xb9, 0x54, 0x9a, 0xe9,
        0x4c,
    ],
    [
        0x35, 0x12, 0x90, 0x22, 0x28, 0x6e, 0xc0, 0x40, 0xbe, 0xf7, 0xdf, 0x1b, 0x1a, 0xa5, 0x51,
        0xae,
    ],
    [
        0xcf, 0x59, 0xa6, 0x48, 0x0f, 0xbc, 0x73, 0xc1, 0x2b, 0xd2, 0x7e, 0xba, 0x3c, 0x61, 0xc1,
        0xa0,
    ],
    [
        0xa1, 0x9d, 0xc5, 0xe9, 0xfd, 0xbd, 0xd6, 0x4a, 0x88, 0x82, 0x28, 0x02, 0x03, 0xcc, 0x6a,
        0x75,
    ],
];

const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// Errors produced by the fixed-input Haraka digests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HarakaError {
    /// An update would exceed the algorithm's fixed input size.
    InputTooLong { limit: usize, attempted: usize },
    /// Finalization was requested before the fixed input was complete.
    IncorrectLength { expected: usize, actual: usize },
    /// The caller supplied less than 32 bytes of output space.
    OutputTooShort { required: usize, actual: usize },
}

impl fmt::Display for HarakaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLong { limit, attempted } => write!(
                f,
                "Haraka input too long: limit is {limit} bytes, attempted {attempted} bytes"
            ),
            Self::IncorrectLength { expected, actual } => write!(
                f,
                "incorrect Haraka input length: expected {expected} bytes, got {actual} bytes"
            ),
            Self::OutputTooShort { required, actual } => write!(
                f,
                "Haraka output too short: need {required} bytes, got {actual} bytes"
            ),
        }
    }
}

impl core::error::Error for HarakaError {}

#[inline]
fn mul_x(value: u8) -> u8 {
    (value << 1) ^ ((value >> 7) * 0x1b)
}

#[inline]
fn aes_enc(state: Block, round_key: &Block) -> Block {
    let mut substituted = [0u8; 16];
    for (output, input) in substituted.iter_mut().zip(state) {
        *output = AES_SBOX[input as usize];
    }

    let shifted = [
        substituted[0],
        substituted[5],
        substituted[10],
        substituted[15],
        substituted[4],
        substituted[9],
        substituted[14],
        substituted[3],
        substituted[8],
        substituted[13],
        substituted[2],
        substituted[7],
        substituted[12],
        substituted[1],
        substituted[6],
        substituted[11],
    ];
    let mut output = [0u8; 16];
    for column in 0..4 {
        let offset = column * 4;
        let a = shifted[offset];
        let b = shifted[offset + 1];
        let c = shifted[offset + 2];
        let d = shifted[offset + 3];
        output[offset] = mul_x(a) ^ mul_x(b) ^ b ^ c ^ d;
        output[offset + 1] = a ^ mul_x(b) ^ mul_x(c) ^ c ^ d;
        output[offset + 2] = a ^ b ^ mul_x(c) ^ mul_x(d) ^ d;
        output[offset + 3] = mul_x(a) ^ a ^ b ^ c ^ mul_x(d);
    }
    for (value, key) in output.iter_mut().zip(round_key) {
        *value ^= key;
    }
    output
}

#[inline]
fn copy_word(output: &mut Block, output_word: usize, input: &Block, input_word: usize) {
    let output_start = output_word * 4;
    let input_start = input_word * 4;
    output[output_start..output_start + 4].copy_from_slice(&input[input_start..input_start + 4]);
}

#[inline]
fn mix256(state: &mut [Block; 2]) {
    let input = *state;
    let mut output = [[0u8; 16]; 2];
    for word in 0..4 {
        copy_word(&mut output[0], word, &input[word & 1], word >> 1);
        copy_word(&mut output[1], word, &input[word & 1], 2 + (word >> 1));
    }
    *state = output;
}

#[inline]
fn mix512(state: &mut [Block; 4]) {
    const MAPPING: [[(usize, usize); 4]; 4] = [
        [(0, 3), (2, 3), (1, 3), (3, 3)],
        [(2, 0), (0, 0), (3, 0), (1, 0)],
        [(2, 1), (0, 1), (3, 1), (1, 1)],
        [(0, 2), (2, 2), (1, 2), (3, 2)],
    ];
    let input = *state;
    let mut output = [[0u8; 16]; 4];
    for output_block in 0..4 {
        for output_word in 0..4 {
            let (input_block, input_word) = MAPPING[output_block][output_word];
            copy_word(
                &mut output[output_block],
                output_word,
                &input[input_block],
                input_word,
            );
        }
    }
    *state = output;
}

fn haraka256_portable(input: &[u8; 32], output: &mut [u8; DIGEST_LENGTH]) {
    let mut state = [[0u8; 16]; 2];
    state[0].copy_from_slice(&input[..16]);
    state[1].copy_from_slice(&input[16..]);

    for round in 0..5 {
        let rc = round * 4;
        state[0] = aes_enc(state[0], &ROUND_CONSTANTS[rc]);
        state[1] = aes_enc(state[1], &ROUND_CONSTANTS[rc + 1]);
        state[0] = aes_enc(state[0], &ROUND_CONSTANTS[rc + 2]);
        state[1] = aes_enc(state[1], &ROUND_CONSTANTS[rc + 3]);
        mix256(&mut state);
    }

    for index in 0..DIGEST_LENGTH {
        output[index] = state[index / 16][index % 16] ^ input[index];
    }
}

fn haraka512_portable(input: &[u8; 64], output: &mut [u8; DIGEST_LENGTH]) {
    let mut state = [[0u8; 16]; 4];
    for (block, bytes) in state.iter_mut().zip(input.chunks_exact(16)) {
        block.copy_from_slice(bytes);
    }

    for round in 0..5 {
        let rc = round * 8;
        for lane in 0..4 {
            state[lane] = aes_enc(state[lane], &ROUND_CONSTANTS[rc + lane]);
        }
        for lane in 0..4 {
            state[lane] = aes_enc(state[lane], &ROUND_CONSTANTS[rc + 4 + lane]);
        }
        mix512(&mut state);
    }

    for index in 0..64 {
        state[index / 16][index % 16] ^= input[index];
    }
    output[..8].copy_from_slice(&state[0][8..]);
    output[8..16].copy_from_slice(&state[1][8..]);
    output[16..24].copy_from_slice(&state[2][..8]);
    output[24..].copy_from_slice(&state[3][..8]);
}

#[cfg(all(feature = "std", any(target_arch = "x86", target_arch = "x86_64")))]
mod aesni {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    use super::ROUND_CONSTANTS;

    #[inline]
    #[target_feature(enable = "aes,sse2")]
    unsafe fn round(state: __m128i, index: usize) -> __m128i {
        unsafe {
            let key = _mm_loadu_si128(ROUND_CONSTANTS[index].as_ptr().cast());
            _mm_aesenc_si128(state, key)
        }
    }

    /// # Safety
    ///
    /// The caller must establish AES and SSE2 support.
    #[target_feature(enable = "aes,sse2")]
    pub(super) unsafe fn haraka256(input: &[u8; 32], output: &mut [u8; 32]) {
        unsafe {
            let original0 = _mm_loadu_si128(input.as_ptr().cast());
            let original1 = _mm_loadu_si128(input.as_ptr().add(16).cast());
            let mut state0 = original0;
            let mut state1 = original1;

            for outer in 0..5 {
                let rc = outer * 4;
                state0 = round(state0, rc);
                state1 = round(state1, rc + 1);
                state0 = round(state0, rc + 2);
                state1 = round(state1, rc + 3);
                let low = _mm_unpacklo_epi32(state0, state1);
                let high = _mm_unpackhi_epi32(state0, state1);
                state0 = low;
                state1 = high;
            }

            state0 = _mm_xor_si128(state0, original0);
            state1 = _mm_xor_si128(state1, original1);
            _mm_storeu_si128(output.as_mut_ptr().cast(), state0);
            _mm_storeu_si128(output.as_mut_ptr().add(16).cast(), state1);
        }
    }

    /// # Safety
    ///
    /// The caller must establish AES and SSE2 support.
    #[target_feature(enable = "aes,sse2")]
    pub(super) unsafe fn haraka512(input: &[u8; 64], output: &mut [u8; 32]) {
        unsafe {
            let originals = [
                _mm_loadu_si128(input.as_ptr().cast()),
                _mm_loadu_si128(input.as_ptr().add(16).cast()),
                _mm_loadu_si128(input.as_ptr().add(32).cast()),
                _mm_loadu_si128(input.as_ptr().add(48).cast()),
            ];
            let mut state = originals;

            for outer in 0..5 {
                let rc = outer * 8;
                for lane in 0..4 {
                    state[lane] = round(state[lane], rc + lane);
                }
                for lane in 0..4 {
                    state[lane] = round(state[lane], rc + 4 + lane);
                }

                let u0 = _mm_unpacklo_epi32(state[0], state[1]);
                let u1 = _mm_unpackhi_epi32(state[0], state[1]);
                let u2 = _mm_unpacklo_epi32(state[2], state[3]);
                let u3 = _mm_unpackhi_epi32(state[2], state[3]);
                state = [
                    _mm_unpackhi_epi32(u1, u3),
                    _mm_unpacklo_epi32(u2, u0),
                    _mm_unpackhi_epi32(u2, u0),
                    _mm_unpacklo_epi32(u1, u3),
                ];
            }

            let mut full = [0u8; 64];
            for lane in 0..4 {
                state[lane] = _mm_xor_si128(state[lane], originals[lane]);
                _mm_storeu_si128(full.as_mut_ptr().add(lane * 16).cast(), state[lane]);
            }
            output[..8].copy_from_slice(&full[8..16]);
            output[8..16].copy_from_slice(&full[24..32]);
            output[16..24].copy_from_slice(&full[32..40]);
            output[24..].copy_from_slice(&full[48..56]);
        }
    }
}

#[inline]
fn haraka256(input: &[u8; 32], output: &mut [u8; DIGEST_LENGTH]) {
    #[cfg(all(feature = "std", any(target_arch = "x86", target_arch = "x86_64")))]
    if std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("sse2") {
        // SAFETY: both target features required by the backend were detected.
        unsafe { aesni::haraka256(input, output) };
        return;
    }
    haraka256_portable(input, output);
}

#[inline]
fn haraka512(input: &[u8; 64], output: &mut [u8; DIGEST_LENGTH]) {
    #[cfg(all(feature = "std", any(target_arch = "x86", target_arch = "x86_64")))]
    if std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("sse2") {
        // SAFETY: both target features required by the backend were detected.
        unsafe { aesni::haraka512(input, output) };
        return;
    }
    haraka512_portable(input, output);
}

macro_rules! define_haraka_digest {
    ($name:ident, $input_length:expr, $algorithm_name:literal, $hash:ident) => {
        #[doc = concat!("The fixed-input ", $algorithm_name, " digest.")]
        #[derive(Clone, Debug)]
        pub struct $name {
            buffer: [u8; $input_length],
            position: usize,
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $name {
            #[doc = concat!("Creates a new ", $algorithm_name, " digest.")]
            pub const fn new() -> Self {
                Self {
                    buffer: [0; $input_length],
                    position: 0,
                }
            }

            /// Returns the number of fixed-input bytes currently buffered.
            pub const fn len(&self) -> usize {
                self.position
            }

            /// Returns whether no input bytes are currently buffered.
            pub const fn is_empty(&self) -> bool {
                self.position == 0
            }
        }

        impl TryDigest for $name {
            type Error = HarakaError;

            fn algorithm_name(&self) -> &str {
                $algorithm_name
            }

            fn digest_size(&self) -> usize {
                DIGEST_LENGTH
            }

            fn byte_length(&self) -> usize {
                $input_length
            }

            fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
                let attempted = self.position.saturating_add(input.len());
                if input.len() > $input_length - self.position {
                    return Err(HarakaError::InputTooLong {
                        limit: $input_length,
                        attempted,
                    });
                }
                let end = self.position + input.len();
                self.buffer[self.position..end].copy_from_slice(input);
                self.position = end;
                Ok(())
            }

            fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
                if self.position != $input_length {
                    return Err(HarakaError::IncorrectLength {
                        expected: $input_length,
                        actual: self.position,
                    });
                }
                if output.len() < DIGEST_LENGTH {
                    return Err(HarakaError::OutputTooShort {
                        required: DIGEST_LENGTH,
                        actual: output.len(),
                    });
                }

                let mut digest = [0u8; DIGEST_LENGTH];
                $hash(&self.buffer, &mut digest);
                output[..DIGEST_LENGTH].copy_from_slice(&digest);
                self.buffer.fill(0);
                self.position = 0;
                Ok(DIGEST_LENGTH)
            }

            fn try_reset(&mut self) -> Result<(), Self::Error> {
                self.buffer.fill(0);
                self.position = 0;
                Ok(())
            }
        }
    };
}

define_haraka_digest!(Haraka256Digest, 32, "Haraka-256", haraka256);
define_haraka_digest!(Haraka512Digest, 64, "Haraka-512", haraka512);

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex<const N: usize>(hex: &str) -> [u8; N] {
        fn digit(value: u8) -> u8 {
            match value {
                b'0'..=b'9' => value - b'0',
                b'a'..=b'f' => value - b'a' + 10,
                b'A'..=b'F' => value - b'A' + 10,
                _ => panic!("invalid hexadecimal digit"),
            }
        }

        assert_eq!(hex.len(), N * 2);
        let bytes = hex.as_bytes();
        let mut output = [0u8; N];
        for index in 0..N {
            output[index] = (digit(bytes[index * 2]) << 4) | digit(bytes[index * 2 + 1]);
        }
        output
    }

    #[test]
    fn appendix_b_vectors() {
        let input256: [u8; 32] = core::array::from_fn(|index| index as u8);
        let mut digest256 = Haraka256Digest::new();
        digest256.try_update(&input256).unwrap();
        let mut output = [0u8; 32];
        digest256.try_do_final(&mut output).unwrap();
        assert_eq!(
            output,
            decode_hex("8027ccb87949774b78d0545fb72bf70c695c2a0923cbd47bba1159efbf2b2c1c")
        );

        let input512: [u8; 64] = core::array::from_fn(|index| index as u8);
        let mut digest512 = Haraka512Digest::new();
        digest512.try_update(&input512).unwrap();
        digest512.try_do_final(&mut output).unwrap();
        assert_eq!(
            output,
            decode_hex("be7f723b4e80a99813b292287f306f625a6d57331cae5f34dd9277b0945be2aa")
        );
    }

    #[test]
    fn bc_monte_carlo_vectors_256() {
        let vectors = [
            (
                decode_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
                decode_hex("e78599d7163ab58f1c90f0171c6fc4e852eb4b8cc29a4af63194fd9977c1de84"),
            ),
            (
                [0xff; 32],
                decode_hex("c4cebda63c00c4cd312f36ea92afd4b0f6048507c5b367326ef9d8fdd2d5c09a"),
            ),
        ];
        for (mut result, expected) in vectors {
            let mut digest = Haraka256Digest::new();
            for _ in 0..1000 {
                digest.try_update(&result).unwrap();
                digest.try_do_final(&mut result).unwrap();
            }
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn bc_monte_carlo_vectors_512() {
        let vectors = [
            (
                core::array::from_fn(|index| index as u8),
                decode_hex("abe210fe673f3b28e70e5100c476d82f61a7e2bdb3d8423fb0a15e5de3d3a4de"),
            ),
            (
                [0xff; 64],
                decode_hex("5f5ecb52c61f5036c96be555d2e18c520ab3ed093954700c283a322d14dbfe02"),
            ),
        ];
        for (mut input, expected) in vectors {
            let mut result = [0u8; 32];
            let mut digest = Haraka512Digest::new();
            for round in 0..1000 {
                digest.try_update(&input).unwrap();
                digest.try_do_final(&mut result).unwrap();
                let offset = if round & 1 == 1 { 0 } else { 32 };
                input[offset..offset + 32].copy_from_slice(&result);
            }
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn fixed_input_errors_preserve_buffer_until_reset() {
        let mut digest = Haraka256Digest::new();
        digest.try_update(&[1; 31]).unwrap();
        assert_eq!(
            digest.try_do_final(&mut [0u8; 32]),
            Err(HarakaError::IncorrectLength {
                expected: 32,
                actual: 31,
            })
        );
        assert_eq!(digest.len(), 31);
        assert_eq!(
            digest.try_update(&[2, 3]),
            Err(HarakaError::InputTooLong {
                limit: 32,
                attempted: 33,
            })
        );
        assert_eq!(digest.len(), 31);

        digest.try_update_byte(2).unwrap();
        assert_eq!(
            digest.try_do_final(&mut [0u8; 31]),
            Err(HarakaError::OutputTooShort {
                required: 32,
                actual: 31,
            })
        );
        assert_eq!(digest.len(), 32);
        digest.try_reset().unwrap();
        assert!(digest.is_empty());
    }

    #[test]
    fn accessors_chunking_clone_and_successful_reset() {
        let input: [u8; 64] = core::array::from_fn(|index| index as u8);
        let mut chunked = Haraka512Digest::new();
        chunked.try_update(&input[..7]).unwrap();
        chunked.try_update(&input[7..]).unwrap();
        let mut cloned = chunked.clone();
        assert_eq!(chunked.algorithm_name(), "Haraka-512");
        assert_eq!(chunked.digest_size(), 32);
        assert_eq!(chunked.byte_length(), 64);

        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        chunked.try_do_final(&mut first).unwrap();
        cloned.try_do_final(&mut second).unwrap();
        assert_eq!(first, second);
        assert!(chunked.is_empty());
    }

    #[cfg(all(feature = "std", any(target_arch = "x86", target_arch = "x86_64")))]
    #[test]
    fn aesni_matches_portable() {
        if !std::is_x86_feature_detected!("aes") || !std::is_x86_feature_detected!("sse2") {
            return;
        }

        for case in 0..16u8 {
            let input256 = core::array::from_fn(|index| (index as u8).wrapping_mul(17) ^ case);
            let input512 = core::array::from_fn(|index| (index as u8).wrapping_mul(29) ^ case);
            let mut portable = [0u8; 32];
            let mut accelerated = [0u8; 32];
            haraka256_portable(&input256, &mut portable);
            unsafe { aesni::haraka256(&input256, &mut accelerated) };
            assert_eq!(portable, accelerated, "Haraka-256 case {case}");

            haraka512_portable(&input512, &mut portable);
            unsafe { aesni::haraka512(&input512, &mut accelerated) };
            assert_eq!(portable, accelerated, "Haraka-512 case {case}");
        }
    }
}
