//! DSTU 7564 (Kupyna) message digest, ported from Bouncy Castle's
//! `Dstu7564Digest`.
//!
//! The standardized 256-, 384-, and 512-bit outputs use either a 512-bit state
//! with 10 rounds or a 1024-bit state with 14 rounds. Compression combines two
//! related permutations as `H <- H ^ P(H ^ M) ^ Q(M)`.

use core::convert::Infallible;

use tc_crypto_core::TryDigest;

use crate::md_buffer::MdBuffer;

const NARROW_COLUMNS: usize = 8;
const WIDE_COLUMNS: usize = 16;
const NARROW_ROUNDS: usize = 10;
const WIDE_ROUNDS: usize = 14;

#[rustfmt::skip]
const S0: [u8; 256] = [
    0xa8, 0x43, 0x5f, 0x06, 0x6b, 0x75, 0x6c, 0x59, 0x71, 0xdf, 0x87, 0x95, 0x17, 0xf0, 0xd8, 0x09,
    0x6d, 0xf3, 0x1d, 0xcb, 0xc9, 0x4d, 0x2c, 0xaf, 0x79, 0xe0, 0x97, 0xfd, 0x6f, 0x4b, 0x45, 0x39,
    0x3e, 0xdd, 0xa3, 0x4f, 0xb4, 0xb6, 0x9a, 0x0e, 0x1f, 0xbf, 0x15, 0xe1, 0x49, 0xd2, 0x93, 0xc6,
    0x92, 0x72, 0x9e, 0x61, 0xd1, 0x63, 0xfa, 0xee, 0xf4, 0x19, 0xd5, 0xad, 0x58, 0xa4, 0xbb, 0xa1,
    0xdc, 0xf2, 0x83, 0x37, 0x42, 0xe4, 0x7a, 0x32, 0x9c, 0xcc, 0xab, 0x4a, 0x8f, 0x6e, 0x04, 0x27,
    0x2e, 0xe7, 0xe2, 0x5a, 0x96, 0x16, 0x23, 0x2b, 0xc2, 0x65, 0x66, 0x0f, 0xbc, 0xa9, 0x47, 0x41,
    0x34, 0x48, 0xfc, 0xb7, 0x6a, 0x88, 0xa5, 0x53, 0x86, 0xf9, 0x5b, 0xdb, 0x38, 0x7b, 0xc3, 0x1e,
    0x22, 0x33, 0x24, 0x28, 0x36, 0xc7, 0xb2, 0x3b, 0x8e, 0x77, 0xba, 0xf5, 0x14, 0x9f, 0x08, 0x55,
    0x9b, 0x4c, 0xfe, 0x60, 0x5c, 0xda, 0x18, 0x46, 0xcd, 0x7d, 0x21, 0xb0, 0x3f, 0x1b, 0x89, 0xff,
    0xeb, 0x84, 0x69, 0x3a, 0x9d, 0xd7, 0xd3, 0x70, 0x67, 0x40, 0xb5, 0xde, 0x5d, 0x30, 0x91, 0xb1,
    0x78, 0x11, 0x01, 0xe5, 0x00, 0x68, 0x98, 0xa0, 0xc5, 0x02, 0xa6, 0x74, 0x2d, 0x0b, 0xa2, 0x76,
    0xb3, 0xbe, 0xce, 0xbd, 0xae, 0xe9, 0x8a, 0x31, 0x1c, 0xec, 0xf1, 0x99, 0x94, 0xaa, 0xf6, 0x26,
    0x2f, 0xef, 0xe8, 0x8c, 0x35, 0x03, 0xd4, 0x7f, 0xfb, 0x05, 0xc1, 0x5e, 0x90, 0x20, 0x3d, 0x82,
    0xf7, 0xea, 0x0a, 0x0d, 0x7e, 0xf8, 0x50, 0x1a, 0xc4, 0x07, 0x57, 0xb8, 0x3c, 0x62, 0xe3, 0xc8,
    0xac, 0x52, 0x64, 0x10, 0xd0, 0xd9, 0x13, 0x0c, 0x12, 0x29, 0x51, 0xb9, 0xcf, 0xd6, 0x73, 0x8d,
    0x81, 0x54, 0xc0, 0xed, 0x4e, 0x44, 0xa7, 0x2a, 0x85, 0x25, 0xe6, 0xca, 0x7c, 0x8b, 0x56, 0x80,
];

#[rustfmt::skip]
const S1: [u8; 256] = [
    0xce, 0xbb, 0xeb, 0x92, 0xea, 0xcb, 0x13, 0xc1, 0xe9, 0x3a, 0xd6, 0xb2, 0xd2, 0x90, 0x17, 0xf8,
    0x42, 0x15, 0x56, 0xb4, 0x65, 0x1c, 0x88, 0x43, 0xc5, 0x5c, 0x36, 0xba, 0xf5, 0x57, 0x67, 0x8d,
    0x31, 0xf6, 0x64, 0x58, 0x9e, 0xf4, 0x22, 0xaa, 0x75, 0x0f, 0x02, 0xb1, 0xdf, 0x6d, 0x73, 0x4d,
    0x7c, 0x26, 0x2e, 0xf7, 0x08, 0x5d, 0x44, 0x3e, 0x9f, 0x14, 0xc8, 0xae, 0x54, 0x10, 0xd8, 0xbc,
    0x1a, 0x6b, 0x69, 0xf3, 0xbd, 0x33, 0xab, 0xfa, 0xd1, 0x9b, 0x68, 0x4e, 0x16, 0x95, 0x91, 0xee,
    0x4c, 0x63, 0x8e, 0x5b, 0xcc, 0x3c, 0x19, 0xa1, 0x81, 0x49, 0x7b, 0xd9, 0x6f, 0x37, 0x60, 0xca,
    0xe7, 0x2b, 0x48, 0xfd, 0x96, 0x45, 0xfc, 0x41, 0x12, 0x0d, 0x79, 0xe5, 0x89, 0x8c, 0xe3, 0x20,
    0x30, 0xdc, 0xb7, 0x6c, 0x4a, 0xb5, 0x3f, 0x97, 0xd4, 0x62, 0x2d, 0x06, 0xa4, 0xa5, 0x83, 0x5f,
    0x2a, 0xda, 0xc9, 0x00, 0x7e, 0xa2, 0x55, 0xbf, 0x11, 0xd5, 0x9c, 0xcf, 0x0e, 0x0a, 0x3d, 0x51,
    0x7d, 0x93, 0x1b, 0xfe, 0xc4, 0x47, 0x09, 0x86, 0x0b, 0x8f, 0x9d, 0x6a, 0x07, 0xb9, 0xb0, 0x98,
    0x18, 0x32, 0x71, 0x4b, 0xef, 0x3b, 0x70, 0xa0, 0xe4, 0x40, 0xff, 0xc3, 0xa9, 0xe6, 0x78, 0xf9,
    0x8b, 0x46, 0x80, 0x1e, 0x38, 0xe1, 0xb8, 0xa8, 0xe0, 0x0c, 0x23, 0x76, 0x1d, 0x25, 0x24, 0x05,
    0xf1, 0x6e, 0x94, 0x28, 0x9a, 0x84, 0xe8, 0xa3, 0x4f, 0x77, 0xd3, 0x85, 0xe2, 0x52, 0xf2, 0x82,
    0x50, 0x7a, 0x2f, 0x74, 0x53, 0xb3, 0x61, 0xaf, 0x39, 0x35, 0xde, 0xcd, 0x1f, 0x99, 0xac, 0xad,
    0x72, 0x2c, 0xdd, 0xd0, 0x87, 0xbe, 0x5e, 0xa6, 0xec, 0x04, 0xc6, 0x03, 0x34, 0xfb, 0xdb, 0x59,
    0xb6, 0xc2, 0x01, 0xf0, 0x5a, 0xed, 0xa7, 0x66, 0x21, 0x7f, 0x8a, 0x27, 0xc7, 0xc0, 0x29, 0xd7,
];

#[rustfmt::skip]
const S2: [u8; 256] = [
    0x93, 0xd9, 0x9a, 0xb5, 0x98, 0x22, 0x45, 0xfc, 0xba, 0x6a, 0xdf, 0x02, 0x9f, 0xdc, 0x51, 0x59,
    0x4a, 0x17, 0x2b, 0xc2, 0x94, 0xf4, 0xbb, 0xa3, 0x62, 0xe4, 0x71, 0xd4, 0xcd, 0x70, 0x16, 0xe1,
    0x49, 0x3c, 0xc0, 0xd8, 0x5c, 0x9b, 0xad, 0x85, 0x53, 0xa1, 0x7a, 0xc8, 0x2d, 0xe0, 0xd1, 0x72,
    0xa6, 0x2c, 0xc4, 0xe3, 0x76, 0x78, 0xb7, 0xb4, 0x09, 0x3b, 0x0e, 0x41, 0x4c, 0xde, 0xb2, 0x90,
    0x25, 0xa5, 0xd7, 0x03, 0x11, 0x00, 0xc3, 0x2e, 0x92, 0xef, 0x4e, 0x12, 0x9d, 0x7d, 0xcb, 0x35,
    0x10, 0xd5, 0x4f, 0x9e, 0x4d, 0xa9, 0x55, 0xc6, 0xd0, 0x7b, 0x18, 0x97, 0xd3, 0x36, 0xe6, 0x48,
    0x56, 0x81, 0x8f, 0x77, 0xcc, 0x9c, 0xb9, 0xe2, 0xac, 0xb8, 0x2f, 0x15, 0xa4, 0x7c, 0xda, 0x38,
    0x1e, 0x0b, 0x05, 0xd6, 0x14, 0x6e, 0x6c, 0x7e, 0x66, 0xfd, 0xb1, 0xe5, 0x60, 0xaf, 0x5e, 0x33,
    0x87, 0xc9, 0xf0, 0x5d, 0x6d, 0x3f, 0x88, 0x8d, 0xc7, 0xf7, 0x1d, 0xe9, 0xec, 0xed, 0x80, 0x29,
    0x27, 0xcf, 0x99, 0xa8, 0x50, 0x0f, 0x37, 0x24, 0x28, 0x30, 0x95, 0xd2, 0x3e, 0x5b, 0x40, 0x83,
    0xb3, 0x69, 0x57, 0x1f, 0x07, 0x1c, 0x8a, 0xbc, 0x20, 0xeb, 0xce, 0x8e, 0xab, 0xee, 0x31, 0xa2,
    0x73, 0xf9, 0xca, 0x3a, 0x1a, 0xfb, 0x0d, 0xc1, 0xfe, 0xfa, 0xf2, 0x6f, 0xbd, 0x96, 0xdd, 0x43,
    0x52, 0xb6, 0x08, 0xf3, 0xae, 0xbe, 0x19, 0x89, 0x32, 0x26, 0xb0, 0xea, 0x4b, 0x64, 0x84, 0x82,
    0x6b, 0xf5, 0x79, 0xbf, 0x01, 0x5f, 0x75, 0x63, 0x1b, 0x23, 0x3d, 0x68, 0x2a, 0x65, 0xe8, 0x91,
    0xf6, 0xff, 0x13, 0x58, 0xf1, 0x47, 0x0a, 0x7f, 0xc5, 0xa7, 0xe7, 0x61, 0x5a, 0x06, 0x46, 0x44,
    0x42, 0x04, 0xa0, 0xdb, 0x39, 0x86, 0x54, 0xaa, 0x8c, 0x34, 0x21, 0x8b, 0xf8, 0x0c, 0x74, 0x67,
];

#[rustfmt::skip]
const S3: [u8; 256] = [
    0x68, 0x8d, 0xca, 0x4d, 0x73, 0x4b, 0x4e, 0x2a, 0xd4, 0x52, 0x26, 0xb3, 0x54, 0x1e, 0x19, 0x1f,
    0x22, 0x03, 0x46, 0x3d, 0x2d, 0x4a, 0x53, 0x83, 0x13, 0x8a, 0xb7, 0xd5, 0x25, 0x79, 0xf5, 0xbd,
    0x58, 0x2f, 0x0d, 0x02, 0xed, 0x51, 0x9e, 0x11, 0xf2, 0x3e, 0x55, 0x5e, 0xd1, 0x16, 0x3c, 0x66,
    0x70, 0x5d, 0xf3, 0x45, 0x40, 0xcc, 0xe8, 0x94, 0x56, 0x08, 0xce, 0x1a, 0x3a, 0xd2, 0xe1, 0xdf,
    0xb5, 0x38, 0x6e, 0x0e, 0xe5, 0xf4, 0xf9, 0x86, 0xe9, 0x4f, 0xd6, 0x85, 0x23, 0xcf, 0x32, 0x99,
    0x31, 0x14, 0xae, 0xee, 0xc8, 0x48, 0xd3, 0x30, 0xa1, 0x92, 0x41, 0xb1, 0x18, 0xc4, 0x2c, 0x71,
    0x72, 0x44, 0x15, 0xfd, 0x37, 0xbe, 0x5f, 0xaa, 0x9b, 0x88, 0xd8, 0xab, 0x89, 0x9c, 0xfa, 0x60,
    0xea, 0xbc, 0x62, 0x0c, 0x24, 0xa6, 0xa8, 0xec, 0x67, 0x20, 0xdb, 0x7c, 0x28, 0xdd, 0xac, 0x5b,
    0x34, 0x7e, 0x10, 0xf1, 0x7b, 0x8f, 0x63, 0xa0, 0x05, 0x9a, 0x43, 0x77, 0x21, 0xbf, 0x27, 0x09,
    0xc3, 0x9f, 0xb6, 0xd7, 0x29, 0xc2, 0xeb, 0xc0, 0xa4, 0x8b, 0x8c, 0x1d, 0xfb, 0xff, 0xc1, 0xb2,
    0x97, 0x2e, 0xf8, 0x65, 0xf6, 0x75, 0x07, 0x04, 0x49, 0x33, 0xe4, 0xd9, 0xb9, 0xd0, 0x42, 0xc7,
    0x6c, 0x90, 0x00, 0x8e, 0x6f, 0x50, 0x01, 0xc5, 0xda, 0x47, 0x3f, 0xcd, 0x69, 0xa2, 0xe2, 0x7a,
    0xa7, 0xc6, 0x93, 0x0f, 0x0a, 0x06, 0xe6, 0x2b, 0x96, 0xa3, 0x1c, 0xaf, 0x6a, 0x12, 0x84, 0x39,
    0xe7, 0xb0, 0x82, 0xf7, 0xfe, 0x9d, 0x87, 0x5c, 0x81, 0x35, 0xde, 0xb4, 0xa5, 0xfc, 0x80, 0xef,
    0xcb, 0xbb, 0x6b, 0x76, 0xba, 0x5a, 0x7d, 0x78, 0x0b, 0x95, 0xe3, 0xad, 0x74, 0x98, 0x3b, 0x36,
    0x64, 0x6d, 0xdc, 0xf0, 0x59, 0xa9, 0x4c, 0x17, 0x7f, 0x91, 0xb8, 0xc9, 0x57, 0x1b, 0xe0, 0x61,
];

/// The two standardized block sizes selected by the requested digest length.
#[derive(Clone)]
enum DstuBuffer {
    Narrow(MdBuffer<64>),
    Wide(MdBuffer<128>),
}

impl DstuBuffer {
    fn byte_length(&self) -> usize {
        match self {
            DstuBuffer::Narrow(_) => 64,
            DstuBuffer::Wide(_) => 128,
        }
    }

    fn update(
        &mut self,
        input: &[u8],
        state: &mut [u64; WIDE_COLUMNS],
        columns: usize,
        rounds: usize,
    ) {
        match self {
            DstuBuffer::Narrow(buf) => {
                buf.update(input, |block| compress(state, block, columns, rounds))
            }
            DstuBuffer::Wide(buf) => {
                buf.update(input, |block| compress(state, block, columns, rounds))
            }
        }
    }

    fn finish(
        &mut self,
        bit_length: &[u8; 12],
        state: &mut [u64; WIDE_COLUMNS],
        columns: usize,
        rounds: usize,
    ) {
        match self {
            DstuBuffer::Narrow(buf) => {
                buf.finish(bit_length, |block| compress(state, block, columns, rounds))
            }
            DstuBuffer::Wide(buf) => {
                buf.finish(bit_length, |block| compress(state, block, columns, rounds))
            }
        }
    }

    fn reset(&mut self) {
        match self {
            DstuBuffer::Narrow(buf) => buf.reset(),
            DstuBuffer::Wide(buf) => buf.reset(),
        }
    }
}

/// Adds `byte_length * 8` to a 96-bit little-endian bit counter.
fn increment_bit_count(bit_count: &mut [u8; 12], byte_length: usize) {
    let mut addend = (byte_length as u128) << 3;
    let mut i = 0;
    while addend != 0 && i < bit_count.len() {
        let sum = bit_count[i] as u128 + (addend & 0xff);
        bit_count[i] = sum as u8;
        addend = (addend >> 8) + (sum >> 8);
        i += 1;
    }
}

fn permutation_p(state: &mut [u64; WIDE_COLUMNS], columns: usize, rounds: usize) {
    for round in 0..rounds {
        let mut rc = round as u64;
        for word in &mut state[..columns] {
            *word ^= rc;
            rc += 0x10;
        }
        shift_rows(state, columns);
        sub_bytes(state, columns);
        mix_columns(state, columns);
    }
}

fn permutation_q(state: &mut [u64; WIDE_COLUMNS], columns: usize, rounds: usize) {
    for round in 0..rounds {
        let mut rc = ((((columns - 1) << 4) ^ round) as u64) << 56 | 0x00f0_f0f0_f0f0_f0f3;
        for word in &mut state[..columns] {
            *word = word.wrapping_add(rc);
            rc = rc.wrapping_sub(0x1000_0000_0000_0000);
        }
        shift_rows(state, columns);
        sub_bytes(state, columns);
        mix_columns(state, columns);
    }
}

/// Cyclically shifts byte rows by 0..7 columns. For the 1024-bit state, row
/// seven is shifted by 11 as required by DSTU 7564.
fn shift_rows(state: &mut [u64; WIDE_COLUMNS], columns: usize) {
    let mut shifted = [0u64; WIDE_COLUMNS];
    for (column, output) in shifted[..columns].iter_mut().enumerate() {
        for row in 0..8 {
            let shift = if columns == WIDE_COLUMNS && row == 7 {
                11
            } else {
                row
            };
            let source = (column + columns - shift) % columns;
            *output |= ((state[source] >> (row * 8)) & 0xff) << (row * 8);
        }
    }
    state[..columns].copy_from_slice(&shifted[..columns]);
}

fn sub_bytes(state: &mut [u64; WIDE_COLUMNS], columns: usize) {
    for word in &mut state[..columns] {
        let input = word.to_le_bytes();
        *word = u64::from_le_bytes([
            S0[input[0] as usize],
            S1[input[1] as usize],
            S2[input[2] as usize],
            S3[input[3] as usize],
            S0[input[4] as usize],
            S1[input[5] as usize],
            S2[input[6] as usize],
            S3[input[7] as usize],
        ]);
    }
}

/// Multiplies a byte column by the Kupyna circulant MDS matrix over GF(2^8).
fn mix_column(column: u64) -> u64 {
    let x1 =
        ((column & 0x7f7f_7f7f_7f7f_7f7f) << 1) ^ (((column & 0x8080_8080_8080_8080) >> 7) * 0x1d);

    let mut u = column.rotate_right(8) ^ column;
    u ^= u.rotate_right(16);
    u ^= column.rotate_right(48);

    let mut v = u ^ column ^ x1;
    v = ((v & 0x3f3f_3f3f_3f3f_3f3f) << 2)
        ^ (((v & 0x8080_8080_8080_8080) >> 6) * 0x1d)
        ^ (((v & 0x4040_4040_4040_4040) >> 6) * 0x1d);

    u ^ v.rotate_right(32) ^ x1.rotate_right(40) ^ x1.rotate_right(48)
}

fn mix_columns(state: &mut [u64; WIDE_COLUMNS], columns: usize) {
    for word in &mut state[..columns] {
        *word = mix_column(*word);
    }
}

fn compress(state: &mut [u64; WIDE_COLUMNS], block: &[u8], columns: usize, rounds: usize) {
    debug_assert_eq!(block.len(), columns * 8);
    let mut p_state = [0u64; WIDE_COLUMNS];
    let mut q_state = [0u64; WIDE_COLUMNS];

    for (column, bytes) in block.chunks_exact(8).enumerate() {
        let word = u64::from_le_bytes(bytes.try_into().expect("8-byte Kupyna word"));
        p_state[column] = state[column] ^ word;
        q_state[column] = word;
    }

    permutation_p(&mut p_state, columns, rounds);
    permutation_q(&mut q_state, columns, rounds);
    for column in 0..columns {
        state[column] ^= p_state[column] ^ q_state[column];
    }
}

/// The DSTU 7564 (Kupyna) digest with a 256-, 384-, or 512-bit output.
#[derive(Clone)]
pub struct Dstu7564Digest {
    state: [u64; WIDE_COLUMNS],
    buffer: DstuBuffer,
    bit_count: [u8; 12],
    output_len: usize,
    columns: usize,
    rounds: usize,
}

impl Dstu7564Digest {
    /// Creates a DSTU 7564 digest with a 256-, 384-, or 512-bit output.
    ///
    /// # Panics
    ///
    /// Panics (mirroring bc's `ArgumentException`) for other output lengths.
    pub fn new(bit_length: usize) -> Self {
        assert!(
            matches!(bit_length, 256 | 384 | 512),
            "DSTU7564: bit length must be one of 256, 384, 512"
        );

        let (buffer, columns, rounds) = if bit_length == 256 {
            (
                DstuBuffer::Narrow(MdBuffer::new()),
                NARROW_COLUMNS,
                NARROW_ROUNDS,
            )
        } else {
            (DstuBuffer::Wide(MdBuffer::new()), WIDE_COLUMNS, WIDE_ROUNDS)
        };
        let mut state = [0u64; WIDE_COLUMNS];
        state[0] = buffer.byte_length() as u64;

        Dstu7564Digest {
            state,
            buffer,
            bit_count: [0; 12],
            output_len: bit_length / 8,
            columns,
            rounds,
        }
    }
}

impl TryDigest for Dstu7564Digest {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        "DSTU7564"
    }

    fn digest_size(&self) -> usize {
        self.output_len
    }

    fn byte_length(&self) -> usize {
        self.buffer.byte_length()
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        increment_bit_count(&mut self.bit_count, input.len());
        let Self {
            state,
            buffer,
            columns,
            rounds,
            ..
        } = self;
        buffer.update(input, state, *columns, *rounds);
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let output_len = self.output_len;
        {
            let Self {
                state,
                buffer,
                bit_count,
                columns,
                rounds,
                ..
            } = self;
            buffer.finish(bit_count, state, *columns, *rounds);

            let mut transformed = *state;
            permutation_p(&mut transformed, *columns, *rounds);
            for column in 0..*columns {
                state[column] ^= transformed[column];
            }

            let needed_columns = output_len / 8;
            for (i, word) in state[*columns - needed_columns..*columns]
                .iter()
                .enumerate()
            {
                output[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
            }
        }
        self.try_reset()?;
        Ok(output_len)
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.state = [0; WIDE_COLUMNS];
        self.state[0] = self.buffer.byte_length() as u64;
        self.buffer.reset();
        self.bit_count = [0; 12];
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::String, vec, vec::Vec};

    use super::*;
    use tc_crypto_core::Digest;

    fn digest_hex(bit_length: usize, input: &[u8]) -> String {
        let mut digest = Dstu7564Digest::new(bit_length);
        digest.update(input);
        let mut output = vec![0u8; digest.digest_size()];
        digest.do_final(&mut output);

        let mut encoded = String::with_capacity(output.len() * 2);
        for byte in output {
            encoded.push_str(&format!("{byte:02x}"));
        }
        encoded
    }

    #[test]
    fn hash_256_vectors() {
        assert_eq!(
            digest_hex(256, b""),
            "cd5101d1ccdf0d1d1f4ada56e888cd724ca1a0838a3521e7131d4fb78d0f5eb6"
        );
        assert_eq!(
            digest_hex(256, b"abc"),
            "0bd1b36109f1318411a0517315aa46b8839df06622a278676f5487996c9cfc04"
        );
        let input: Vec<u8> = (0..64).map(|i| i as u8).collect();
        assert_eq!(
            digest_hex(256, &input),
            "08f4ee6f1be6903b324c4e27990cb24ef69dd58dbe84813ee0a52f6631239875"
        );
    }

    #[test]
    fn hash_384_vector() {
        let input: Vec<u8> = (0..95).map(|i| i as u8).collect();
        assert_eq!(
            digest_hex(384, &input),
            "d9021692d84e5175735654846ba751e6d0ed0fac36dfbc0841287dcb0b5584c7\
             5016c3decc2a6e47c50b2f3811e351b8"
        );
    }

    #[test]
    fn hash_512_vectors() {
        assert_eq!(
            digest_hex(512, b""),
            "656b2f4cd71462388b64a37043ea55dbe445d452aecd46c3298343314ef04019\
             bcfa3f04265a9857f91be91fce197096187ceda78c9c1c021c294a0689198538"
        );
        let input: Vec<u8> = (0..64).map(|i| i as u8).collect();
        assert_eq!(
            digest_hex(512, &input),
            "3813e2109118cdfb5a6d5e72f7208dccc80a2dfb3afdfb02f46992b5edbe536b\
             3560dd1d7e29c6f53978af58b444e37ba685c0dd910533ba5d78efffc13de62a"
        );
    }

    #[test]
    fn narrow_padding_boundaries() {
        let vectors = [
            (
                51,
                "6f8f0a3f8261af77581ab01cb89d4cb5ed87ca1d9954f11d5586e94b45c82fb8",
            ),
            (
                52,
                "8b6fe2ba77e684b2a1ac82232f4efc49f681cd18c82a0cfff530186a2fc642d2",
            ),
            (
                53,
                "837f2b0cbe39a4defdfcb44272288d4091cab850161c70695d7831fc5f00e171",
            ),
            (
                54,
                "21d423d5b8c7f18a0da42cdd95b36b66344125e2adc6edeab5899926442113bc",
            ),
            (
                55,
                "0e7bf74464b81b3ae7d904170776d29f4b02a7227da578dd562d01027af7fd0e",
            ),
            (
                56,
                "badea1f49cbcec94acec52b4c695acdddd786cca5a6763929f341a58c5134b3b",
            ),
            (
                57,
                "a13b5f6f53ee043292ed65b66c1d49759be4d2fe0c2f6148f2416487965f7bde",
            ),
            (
                63,
                "03a44a02c9ffafb43addb290bbcf3b8168f624e8cbd332dc6a9dc7df9d39cbc2",
            ),
            (
                64,
                "08f4ee6f1be6903b324c4e27990cb24ef69dd58dbe84813ee0a52f6631239875",
            ),
            (
                65,
                "a81c2fb92351f370050b7c36cd51736d5603a50ec1106cbd5fe1c9be2e5c77a6",
            ),
        ];

        for (length, expected) in vectors {
            let input: Vec<u8> = (0..length).map(|i| i as u8).collect();
            assert_eq!(digest_hex(256, &input), expected, "length {length}");
        }
    }

    #[test]
    fn accessors_clone_chunking_and_reset() {
        for bits in [256, 384, 512] {
            let input: Vec<u8> = (0..300).map(|i| i as u8).collect();
            let mut whole = Dstu7564Digest::new(bits);
            assert_eq!(whole.algorithm_name(), "DSTU7564");
            assert_eq!(whole.digest_size(), bits / 8);
            assert_eq!(whole.byte_length(), if bits == 256 { 64 } else { 128 });
            whole.update(&input);

            let mut cloned = whole.clone();
            let mut expected = vec![0u8; whole.digest_size()];
            let mut cloned_output = vec![0u8; cloned.digest_size()];
            whole.do_final(&mut expected);
            cloned.do_final(&mut cloned_output);
            assert_eq!(cloned_output, expected);

            let mut chunked = Dstu7564Digest::new(bits);
            chunked.update(&input[..63]);
            chunked.update(&input[63..129]);
            chunked.update(&input[129..]);
            let mut actual = vec![0u8; chunked.digest_size()];
            chunked.do_final(&mut actual);
            assert_eq!(actual, expected);

            chunked.do_final(&mut actual);
            assert_eq!(actual, hex_to_vec(&digest_hex(bits, b"")));
        }
    }

    #[test]
    fn bit_counter_carries_across_bytes() {
        let mut count = [0u8; 12];
        count[0] = 0xf8;
        count[1] = 0xff;
        increment_bit_count(&mut count, 1);
        assert_eq!(&count[..3], &[0, 0, 1]);
    }

    #[test]
    #[should_panic(expected = "DSTU7564: bit length must be one of 256, 384, 512")]
    fn rejects_non_standard_size() {
        let _ = Dstu7564Digest::new(128);
    }

    fn hex_to_vec(input: &str) -> Vec<u8> {
        (0..input.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&input[i..i + 2], 16).unwrap())
            .collect()
    }
}
