//! Generalised Rijndael engine, key schedule, and round transforms.
//!
//! The state is four 64-bit rows (`A0..A3`), each holding `BC = block_bits / 4`
//! bits packed little-endian by column, mirroring Bouncy Castle's `long`-based
//! reference. All arithmetic is over `u64`; only the low `BC` bits are ever live.

use alloc::vec;
use alloc::vec::Vec;

use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};

use super::tables::{ALOG, LOG, RCON, S, SHIFTS0, SHIFTS1, SI};
use super::{BlockCipherError, RIJNDAEL_BLOCK_BITS, RijndaelParams};

/// Generalised Rijndael with a configurable block size.
pub struct RijndaelEngine {
    /// 每列位元數 BC = block_bits / 4(32/40/48/56/64)。
    bc: u32,
    /// 只保留低 BC 位的遮罩。
    bc_mask: u64,
    block_bits: usize,
    /// 加密列位移量(位元)。
    shifts0: [u32; 4],
    /// 解密列位移量(位元)。
    shifts1: [u32; 4],
    /// 每輪金鑰(長度 ROUNDS+1);init 前為 `None` = 未初始化。
    working_key: Option<Vec<[u64; 4]>>,
    for_encryption: bool,
}

impl RijndaelEngine {
    /// Creates an uninitialised engine for a 128/160/192/224/256-bit block.
    pub fn new(block_bits: usize) -> Result<Self, BlockCipherError> {
        if !RIJNDAEL_BLOCK_BITS.contains(&block_bits) {
            return Err(BlockCipherError::InvalidBlockSize(block_bits));
        }
        let bc = (block_bits / 4) as u32;
        let index = (block_bits - 128) / 32;
        Ok(Self {
            bc,
            bc_mask: if bc == 64 { u64::MAX } else { (1u64 << bc) - 1 },
            block_bits,
            shifts0: SHIFTS0[index],
            shifts1: SHIFTS1[index],
            working_key: None,
            for_encryption: false,
        })
    }

    /// Block length in bytes (`BC / 2`).
    fn block_bytes(&self) -> usize {
        (self.bc / 2) as usize
    }

    // --- byte <-> row packing ---

    fn unpack(&self, input: &[u8]) -> [u64; 4] {
        let mut a = [0u64; 4];
        let mut index = 0;
        for j in (0..self.bc).step_by(8) {
            for row in a.iter_mut() {
                *row |= u64::from(input[index]) << j;
                index += 1;
            }
        }
        a
    }

    fn pack(&self, a: &[u64; 4], output: &mut [u8]) {
        let mut index = 0;
        for j in (0..self.bc).step_by(8) {
            for row in a {
                output[index] = (row >> j) as u8;
                index += 1;
            }
        }
    }

    // --- round transforms ---

    /// Rotates the live `BC`-bit row right by `shift` bits.
    fn shift(&self, r: u64, shift: u32) -> u64 {
        ((r >> shift) | (r << (self.bc - shift))) & self.bc_mask
    }

    fn shift_row(&self, a: &mut [u64; 4], shifts: &[u32; 4]) {
        a[1] = self.shift(a[1], shifts[1]);
        a[2] = self.shift(a[2], shifts[2]);
        a[3] = self.shift(a[3], shifts[3]);
    }

    fn apply_s(&self, r: u64, sbox: &[u8; 256]) -> u64 {
        let mut res = 0u64;
        for j in (0..self.bc).step_by(8) {
            res |= u64::from(sbox[((r >> j) & 0xff) as usize]) << j;
        }
        res
    }

    fn substitution(&self, a: &mut [u64; 4], sbox: &[u8; 256]) {
        for row in a.iter_mut() {
            *row = self.apply_s(*row, sbox);
        }
    }

    fn mix_column(&self, a: &mut [u64; 4]) {
        let mut r = [0u64; 4];
        for j in (0..self.bc).step_by(8) {
            let b = [
                ((a[0] >> j) & 0xff) as i32,
                ((a[1] >> j) & 0xff) as i32,
                ((a[2] >> j) & 0xff) as i32,
                ((a[3] >> j) & 0xff) as i32,
            ];
            for (row, out) in r.iter_mut().enumerate() {
                let x = mul2(b[row]) ^ mul3(b[(row + 1) % 4]) ^ b[(row + 2) % 4] ^ b[(row + 3) % 4];
                *out |= u64::from((x & 0xff) as u8) << j;
            }
        }
        *a = r;
    }

    fn inv_mix_column(&self, a: &mut [u64; 4]) {
        let mut r = [0u64; 4];
        for j in (0..self.bc).step_by(8) {
            // 預先查對數表;0 以 -1 表示(對應 bc 的判斷)。
            let b = [
                pre_log(((a[0] >> j) & 0xff) as i32),
                pre_log(((a[1] >> j) & 0xff) as i32),
                pre_log(((a[2] >> j) & 0xff) as i32),
                pre_log(((a[3] >> j) & 0xff) as i32),
            ];
            for (row, out) in r.iter_mut().enumerate() {
                let x = mul_e(b[row])
                    ^ mul_b(b[(row + 1) % 4])
                    ^ mul_d(b[(row + 2) % 4])
                    ^ mul_9(b[(row + 3) % 4]);
                *out |= u64::from((x & 0xff) as u8) << j;
            }
        }
        *a = r;
    }

    fn encrypt_block(&self, a: &mut [u64; 4], rk: &[[u64; 4]]) {
        let rounds = rk.len() - 1;
        key_addition(a, &rk[0]);
        for round in rk.iter().take(rounds).skip(1) {
            self.substitution(a, &S);
            self.shift_row(a, &self.shifts0);
            self.mix_column(a);
            key_addition(a, round);
        }
        self.substitution(a, &S);
        self.shift_row(a, &self.shifts0);
        key_addition(a, &rk[rounds]);
    }

    fn decrypt_block(&self, a: &mut [u64; 4], rk: &[[u64; 4]]) {
        let rounds = rk.len() - 1;
        key_addition(a, &rk[rounds]);
        self.substitution(a, &SI);
        self.shift_row(a, &self.shifts1);
        for round in (1..rounds).rev() {
            key_addition(a, &rk[round]);
            self.inv_mix_column(a);
            self.substitution(a, &SI);
            self.shift_row(a, &self.shifts1);
        }
        key_addition(a, &rk[0]);
    }

    /// Expands the key into `ROUNDS + 1` round keys (four rows each).
    fn generate_working_key(&self, key: &[u8]) -> Vec<[u64; 4]> {
        let key_bits = key.len() * 8;
        let kc = key.len() / 4; // 4/5/6/7/8
        let columns = (self.bc / 8) as usize; // BC / 8
        let rounds = if key_bits >= self.block_bits {
            kc + 6
        } else {
            columns + 6
        };
        let total = (rounds + 1) * columns;
        let bc = self.bc as usize;

        // tk[row][col]:金鑰依 column-major 填入。
        let mut tk = [[0u8; 8]; 4];
        for (i, &byte) in key.iter().enumerate() {
            tk[i % 4][i / 4] = byte;
        }

        let mut w = vec![[0u64; 4]; rounds + 1];
        let mut t = 0usize;

        let copy_tk = |tk: &[[u8; 8]; 4], w: &mut Vec<[u64; 4]>, t: &mut usize| {
            let mut j = 0;
            while j < kc && *t < total {
                for i in 0..4 {
                    w[*t / columns][i] |= u64::from(tk[i][j]) << ((*t * 8) % bc);
                }
                j += 1;
                *t += 1;
            }
        };

        copy_tk(&tk, &mut w, &mut t);

        let mut rconpointer = 0;
        while t < total {
            for i in 0..4 {
                tk[i][0] ^= S[tk[(i + 1) % 4][kc - 1] as usize];
            }
            tk[0][0] ^= RCON[rconpointer];
            rconpointer += 1;

            if kc <= 6 {
                for j in 1..kc {
                    for row in &mut tk {
                        row[j] ^= row[j - 1];
                    }
                }
            } else {
                for j in 1..4 {
                    for row in &mut tk {
                        row[j] ^= row[j - 1];
                    }
                }
                for row in &mut tk {
                    row[4] ^= S[row[3] as usize];
                }
                for j in 5..kc {
                    for row in &mut tk {
                        row[j] ^= row[j - 1];
                    }
                }
            }

            copy_tk(&tk, &mut w, &mut t);
        }
        w
    }
}

impl BlockCipher for RijndaelEngine {
    type Error = BlockCipherError;

    fn algorithm_name(&self) -> &str {
        "Rijndael"
    }

    fn block_size(&self) -> usize {
        self.block_bytes()
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if self.working_key.is_none() {
            return Err(BlockCipherError::NotInitialised);
        }
        let bytes = self.block_bytes();
        if input.len() < bytes || output.len() < bytes {
            return Err(BlockCipherError::BufferTooShort);
        }
        let rk = self.working_key.as_deref().unwrap();
        let mut a = self.unpack(input);
        if self.for_encryption {
            self.encrypt_block(&mut a, rk);
        } else {
            self.decrypt_block(&mut a, rk);
        }
        self.pack(&a, output);
        Ok(bytes)
    }
}

impl BlockCipherInit for RijndaelEngine {
    type Params<'a> = RijndaelParams;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        self.working_key = Some(self.generate_working_key(params.key()));
        self.for_encryption = direction == CipherDirection::Encrypt;
        Ok(())
    }
}

// --- GF(2^8) multiply helpers (log/antilog table lookups) ---

/// Maps a byte to its log, or `-1` for zero (Bouncy Castle's `InvMixColumn`
/// pre-lookup convention).
fn pre_log(b: i32) -> i32 {
    if b != 0 {
        i32::from(LOG[b as usize])
    } else {
        -1
    }
}

fn mul2(b: i32) -> i32 {
    if b != 0 {
        i32::from(ALOG[25 + LOG[b as usize] as usize])
    } else {
        0
    }
}

fn mul3(b: i32) -> i32 {
    if b != 0 {
        i32::from(ALOG[1 + LOG[b as usize] as usize])
    } else {
        0
    }
}

/// Antilog lookup at `offset + log` for the inverse-mix multiplies; `log < 0`
/// (i.e. a zero input byte) yields zero.
fn alog_at(offset: usize, log: i32) -> i32 {
    if log >= 0 {
        i32::from(ALOG[offset + log as usize])
    } else {
        0
    }
}

fn mul_9(log: i32) -> i32 {
    alog_at(199, log)
}

fn mul_b(log: i32) -> i32 {
    alog_at(104, log)
}

fn mul_d(log: i32) -> i32 {
    alog_at(238, log)
}

fn mul_e(log: i32) -> i32 {
    alog_at(223, log)
}

/// Adds a round key into the state (an involution).
fn key_addition(a: &mut [u64; 4], rk: &[u64; 4]) {
    for (word, &k) in a.iter_mut().zip(rk) {
        *word ^= k;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_block_size() {
        assert!(matches!(
            RijndaelEngine::new(64),
            Err(BlockCipherError::InvalidBlockSize(64))
        ));
    }

    #[test]
    fn accessors_and_pre_init_errors() {
        let mut engine = RijndaelEngine::new(128).unwrap();
        assert_eq!(engine.algorithm_name(), "Rijndael");
        assert_eq!(engine.block_size(), 16);
        assert_eq!(
            engine.process_block(&[0u8; 16], &mut [0u8; 16]),
            Err(BlockCipherError::NotInitialised)
        );
    }

    #[test]
    fn block_size_scales_with_configuration() {
        assert_eq!(RijndaelEngine::new(256).unwrap().block_size(), 32);
    }
}
