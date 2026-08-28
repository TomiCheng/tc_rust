//! Twofish block-cipher engine, key schedule, and round functions.

use tc_crypto_core::BlockCipher;

use super::{TWOFISH_BLOCK_BYTES, BlockCipherError, TwofishParams};

const ROUNDS: usize = 16;
const INPUT_WHITEN: usize = 0;
const OUTPUT_WHITEN: usize = 4;
const ROUND_SUBKEYS: usize = 8;
const TOTAL_SUBKEYS: usize = ROUND_SUBKEYS + 2 * ROUNDS;
const SK_STEP: u32 = 0x0202_0202;
const SK_BUMP: u32 = 0x0101_0101;

const GF256_FDBK: u32 = 0x169;
const GF256_FDBK_2: u32 = GF256_FDBK / 2;
const GF256_FDBK_4: u32 = GF256_FDBK / 4;
const RS_GF_FDBK: u32 = 0x14d;

#[rustfmt::skip]
const Q0_T: [[u8; 16]; 4] = [
    [8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4],
    [14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13],
    [11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1],
    [13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10],
];

#[rustfmt::skip]
const Q1_T: [[u8; 16]; 4] = [
    [2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5],
    [1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8],
    [4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15],
    [11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10],
];

const Q0: [u8; 256] = make_q(&Q0_T);
const Q1: [u8; 256] = make_q(&Q1_T);
const MDS: [[u32; 256]; 4] = make_mds();

struct KeySchedule {
    subkeys: [u32; TOTAL_SUBKEYS],
    sboxes: [u32; 1024],
}

/// Twofish with a 128-bit block and a 128-, 192-, or 256-bit key.
pub struct TwofishEngine {
    encrypting: bool,
    schedule: Option<KeySchedule>,
}

impl TwofishEngine {
    /// Creates an uninitialised engine.
    pub const fn new() -> Self {
        Self {
            encrypting: false,
            schedule: None,
        }
    }
}

impl Default for TwofishEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockCipher for TwofishEngine {
    type Params<'a> = TwofishParams;
    type Error = BlockCipherError;

    fn algorithm_name(&self) -> &str {
        "Twofish"
    }

    fn block_size(&self) -> usize {
        TWOFISH_BLOCK_BYTES
    }

    fn init(&mut self, for_encryption: bool, params: &Self::Params<'_>) -> Result<(), Self::Error> {
        self.schedule = Some(expand_key(params.key()));
        self.encrypting = for_encryption;
        Ok(())
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let schedule = self.schedule.as_ref().ok_or(BlockCipherError::NotInitialised)?;
        if input.len() < TWOFISH_BLOCK_BYTES || output.len() < TWOFISH_BLOCK_BYTES {
            return Err(BlockCipherError::BufferTooShort);
        }

        if self.encrypting {
            encrypt_block(schedule, input, output);
        } else {
            decrypt_block(schedule, input, output);
        }
        Ok(TWOFISH_BLOCK_BYTES)
    }
}

fn expand_key(key: &[u8]) -> KeySchedule {
    let key_words = key.len() / 8;
    let mut even = [0u32; 4];
    let mut odd = [0u32; 4];
    let mut sbox_keys = [0u32; 4];

    for i in 0..key_words {
        let offset = i * 8;
        even[i] = read_word(key, offset);
        odd[i] = read_word(key, offset + 4);
        sbox_keys[key_words - 1 - i] = rs_mds_encode(even[i], odd[i]);
    }

    let mut subkeys = [0u32; TOTAL_SUBKEYS];
    for i in 0..TOTAL_SUBKEYS / 2 {
        let q = (i as u32).wrapping_mul(SK_STEP);
        let mut a = f32(q, &even, key_words);
        let b = f32(q.wrapping_add(SK_BUMP), &odd, key_words).rotate_left(8);
        a = a.wrapping_add(b);
        subkeys[i * 2] = a;
        subkeys[i * 2 + 1] = a.wrapping_add(b).rotate_left(9);
    }

    let mut sboxes = [0u32; 1024];
    for i in 0..256 {
        let [b0, b1, b2, b3] = keyed_bytes(i as u8, &sbox_keys, key_words);
        sboxes[i * 2] = MDS[0][b0 as usize];
        sboxes[i * 2 + 1] = MDS[1][b1 as usize];
        sboxes[i * 2 + 0x200] = MDS[2][b2 as usize];
        sboxes[i * 2 + 0x201] = MDS[3][b3 as usize];
    }

    KeySchedule { subkeys, sboxes }
}

fn encrypt_block(schedule: &KeySchedule, input: &[u8], output: &mut [u8]) {
    let k = &schedule.subkeys;
    let mut x0 = read_word(input, 0) ^ k[INPUT_WHITEN];
    let mut x1 = read_word(input, 4) ^ k[INPUT_WHITEN + 1];
    let mut x2 = read_word(input, 8) ^ k[INPUT_WHITEN + 2];
    let mut x3 = read_word(input, 12) ^ k[INPUT_WHITEN + 3];

    let mut key_index = ROUND_SUBKEYS;
    for _ in (0..ROUNDS).step_by(2) {
        let t0 = fe32_0(&schedule.sboxes, x0);
        let t1 = fe32_3(&schedule.sboxes, x1);
        x2 ^= t0.wrapping_add(t1).wrapping_add(k[key_index]);
        key_index += 1;
        x2 = x2.rotate_right(1);
        x3 = x3.rotate_left(1)
            ^ t0.wrapping_add(t1.wrapping_mul(2))
                .wrapping_add(k[key_index]);
        key_index += 1;

        let t0 = fe32_0(&schedule.sboxes, x2);
        let t1 = fe32_3(&schedule.sboxes, x3);
        x0 ^= t0.wrapping_add(t1).wrapping_add(k[key_index]);
        key_index += 1;
        x0 = x0.rotate_right(1);
        x1 = x1.rotate_left(1)
            ^ t0.wrapping_add(t1.wrapping_mul(2))
                .wrapping_add(k[key_index]);
        key_index += 1;
    }

    write_word(output, 0, x2 ^ k[OUTPUT_WHITEN]);
    write_word(output, 4, x3 ^ k[OUTPUT_WHITEN + 1]);
    write_word(output, 8, x0 ^ k[OUTPUT_WHITEN + 2]);
    write_word(output, 12, x1 ^ k[OUTPUT_WHITEN + 3]);
}

fn decrypt_block(schedule: &KeySchedule, input: &[u8], output: &mut [u8]) {
    let k = &schedule.subkeys;
    let mut x2 = read_word(input, 0) ^ k[OUTPUT_WHITEN];
    let mut x3 = read_word(input, 4) ^ k[OUTPUT_WHITEN + 1];
    let mut x0 = read_word(input, 8) ^ k[OUTPUT_WHITEN + 2];
    let mut x1 = read_word(input, 12) ^ k[OUTPUT_WHITEN + 3];

    let mut key_index = ROUND_SUBKEYS + 2 * ROUNDS;
    for _ in (0..ROUNDS).step_by(2) {
        let t0 = fe32_0(&schedule.sboxes, x2);
        let t1 = fe32_3(&schedule.sboxes, x3);
        key_index -= 1;
        x1 ^= t0
            .wrapping_add(t1.wrapping_mul(2))
            .wrapping_add(k[key_index]);
        key_index -= 1;
        x0 = x0.rotate_left(1) ^ t0.wrapping_add(t1).wrapping_add(k[key_index]);
        x1 = x1.rotate_right(1);

        let t0 = fe32_0(&schedule.sboxes, x0);
        let t1 = fe32_3(&schedule.sboxes, x1);
        key_index -= 1;
        x3 ^= t0
            .wrapping_add(t1.wrapping_mul(2))
            .wrapping_add(k[key_index]);
        key_index -= 1;
        x2 = x2.rotate_left(1) ^ t0.wrapping_add(t1).wrapping_add(k[key_index]);
        x3 = x3.rotate_right(1);
    }

    write_word(output, 0, x0 ^ k[INPUT_WHITEN]);
    write_word(output, 4, x1 ^ k[INPUT_WHITEN + 1]);
    write_word(output, 8, x2 ^ k[INPUT_WHITEN + 2]);
    write_word(output, 12, x3 ^ k[INPUT_WHITEN + 3]);
}

fn f32(x: u32, key: &[u32; 4], key_words: usize) -> u32 {
    let [b0, b1, b2, b3] = keyed_bytes_from_word(x, key, key_words);
    MDS[0][b0 as usize] ^ MDS[1][b1 as usize] ^ MDS[2][b2 as usize] ^ MDS[3][b3 as usize]
}

fn keyed_bytes(value: u8, key: &[u32; 4], key_words: usize) -> [u8; 4] {
    keyed_bytes_inner([value; 4], key, key_words)
}

fn keyed_bytes_from_word(value: u32, key: &[u32; 4], key_words: usize) -> [u8; 4] {
    keyed_bytes_inner(value.to_le_bytes(), key, key_words)
}

fn keyed_bytes_inner(mut b: [u8; 4], key: &[u32; 4], key_words: usize) -> [u8; 4] {
    if key_words == 4 {
        b[0] = Q1[b[0] as usize] ^ byte(key[3], 0);
        b[1] = Q0[b[1] as usize] ^ byte(key[3], 1);
        b[2] = Q0[b[2] as usize] ^ byte(key[3], 2);
        b[3] = Q1[b[3] as usize] ^ byte(key[3], 3);
    }
    if key_words >= 3 {
        b[0] = Q1[b[0] as usize] ^ byte(key[2], 0);
        b[1] = Q1[b[1] as usize] ^ byte(key[2], 1);
        b[2] = Q0[b[2] as usize] ^ byte(key[2], 2);
        b[3] = Q0[b[3] as usize] ^ byte(key[2], 3);
    }

    [
        Q0[(Q0[b[0] as usize] ^ byte(key[1], 0)) as usize] ^ byte(key[0], 0),
        Q0[(Q1[b[1] as usize] ^ byte(key[1], 1)) as usize] ^ byte(key[0], 1),
        Q1[(Q0[b[2] as usize] ^ byte(key[1], 2)) as usize] ^ byte(key[0], 2),
        Q1[(Q1[b[3] as usize] ^ byte(key[1], 3)) as usize] ^ byte(key[0], 3),
    ]
}

fn fe32_0(sboxes: &[u32; 1024], x: u32) -> u32 {
    let b = x.to_le_bytes();
    sboxes[2 * b[0] as usize]
        ^ sboxes[1 + 2 * b[1] as usize]
        ^ sboxes[0x200 + 2 * b[2] as usize]
        ^ sboxes[0x201 + 2 * b[3] as usize]
}

fn fe32_3(sboxes: &[u32; 1024], x: u32) -> u32 {
    let b = x.to_le_bytes();
    sboxes[2 * b[3] as usize]
        ^ sboxes[1 + 2 * b[0] as usize]
        ^ sboxes[0x200 + 2 * b[1] as usize]
        ^ sboxes[0x201 + 2 * b[2] as usize]
}

fn rs_mds_encode(k0: u32, k1: u32) -> u32 {
    let mut r = k1;
    for _ in 0..4 {
        r = rs_rem(r);
    }
    r ^= k0;
    for _ in 0..4 {
        r = rs_rem(r);
    }
    r
}

fn rs_rem(x: u32) -> u32 {
    let b = x >> 24;
    let g2 = ((b << 1) ^ if b & 0x80 != 0 { RS_GF_FDBK } else { 0 }) & 0xff;
    let g3 = (b >> 1 ^ if b & 1 != 0 { RS_GF_FDBK >> 1 } else { 0 }) ^ g2;
    (x << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b
}

const fn make_q(t: &[[u8; 16]; 4]) -> [u8; 256] {
    let mut q = [0u8; 256];
    let mut x = 0;
    while x < 256 {
        let a0 = (x >> 4) as u8;
        let b0 = (x & 15) as u8;
        let a1 = a0 ^ b0;
        let b1 = a0 ^ ror4(b0) ^ ((a0 << 3) & 8);
        let a2 = t[0][a1 as usize];
        let b2 = t[1][b1 as usize];
        let a3 = a2 ^ b2;
        let b3 = a2 ^ ror4(b2) ^ ((a2 << 3) & 8);
        let a4 = t[2][a3 as usize];
        let b4 = t[3][b3 as usize];
        q[x] = (b4 << 4) | a4;
        x += 1;
    }
    q
}

const fn ror4(x: u8) -> u8 {
    ((x >> 1) | (x << 3)) & 15
}

const fn make_mds() -> [[u32; 256]; 4] {
    let mut mds = [[0u32; 256]; 4];
    let mut i = 0;
    while i < 256 {
        let q0 = Q0[i] as u32;
        let q1 = Q1[i] as u32;
        let x0 = mx_x(q0);
        let y0 = mx_y(q0);
        let x1 = mx_x(q1);
        let y1 = mx_y(q1);
        mds[0][i] = q1 | (x1 << 8) | (y1 << 16) | (y1 << 24);
        mds[1][i] = y0 | (y0 << 8) | (x0 << 16) | (q0 << 24);
        mds[2][i] = x1 | (y1 << 8) | (q1 << 16) | (y1 << 24);
        mds[3][i] = x0 | (q0 << 8) | (y0 << 16) | (x0 << 24);
        i += 1;
    }
    mds
}

const fn mx_x(x: u32) -> u32 {
    x ^ lfsr2(x)
}

const fn mx_y(x: u32) -> u32 {
    x ^ lfsr1(x) ^ lfsr2(x)
}

const fn lfsr1(x: u32) -> u32 {
    (x >> 1) ^ if x & 1 != 0 { GF256_FDBK_2 } else { 0 }
}

const fn lfsr2(x: u32) -> u32 {
    (x >> 2) ^ if x & 2 != 0 { GF256_FDBK_2 } else { 0 } ^ if x & 1 != 0 { GF256_FDBK_4 } else { 0 }
}

fn byte(value: u32, index: usize) -> u8 {
    value.to_le_bytes()[index]
}

fn read_word(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(input[offset..offset + 4].try_into().unwrap())
}

fn write_word(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_q_permutations_match_bc_boundaries() {
        assert_eq!(&Q0[..4], &[0xa9, 0x67, 0xb3, 0xe8]);
        assert_eq!(&Q0[252..], &[0x4a, 0x5e, 0xc1, 0xe0]);
        assert_eq!(&Q1[..4], &[0x75, 0xf3, 0xc6, 0xf4]);
        assert_eq!(&Q1[252..], &[0x55, 0x09, 0xbe, 0x91]);
    }

    #[test]
    fn accessors_and_pre_init_errors() {
        let mut engine = TwofishEngine::new();
        assert_eq!(engine.algorithm_name(), "Twofish");
        assert_eq!(engine.block_size(), TWOFISH_BLOCK_BYTES);
        assert_eq!(
            engine.process_block(&[0u8; 16], &mut [0u8; 16]),
            Err(BlockCipherError::NotInitialised)
        );
    }

    #[test]
    fn short_buffers_are_rejected() {
        let params = TwofishParams::new(&[0u8; 16]).unwrap();
        let mut engine = TwofishEngine::new();
        engine.init(true, &params).unwrap();
        assert_eq!(
            engine.process_block(&[0u8; 15], &mut [0u8; 16]),
            Err(BlockCipherError::BufferTooShort)
        );
        assert_eq!(
            engine.process_block(&[0u8; 16], &mut [0u8; 15]),
            Err(BlockCipherError::BufferTooShort)
        );
    }
}
