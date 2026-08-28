//! CAST5 key schedule and block transformation.

use crate::cast_common::{f1, f2, f3};

use super::{CAST5_BLOCK_BYTES, tables::*};

const MAX_ROUNDS: usize = 16;
const REDUCED_ROUNDS: usize = 12;

pub(super) struct Cast5KeySchedule {
    masking: [u32; MAX_ROUNDS],
    rotations: [u32; MAX_ROUNDS],
    rounds: usize,
}

impl Cast5KeySchedule {
    pub(super) const fn new() -> Self {
        Self {
            masking: [0; MAX_ROUNDS],
            rotations: [0; MAX_ROUNDS],
            rounds: MAX_ROUNDS,
        }
    }

    pub(super) fn set_key(&mut self, key: &[u8]) {
        self.masking = [0; MAX_ROUNDS];
        self.rotations = [0; MAX_ROUNDS];
        self.rounds = if key.len() <= 10 {
            REDUCED_ROUNDS
        } else {
            MAX_ROUNDS
        };

        let mut x = [0u8; 16];
        let mut z = [0u8; 16];
        x[..key.len()].copy_from_slice(key);

        x_to_z(&x, &mut z);
        extract_a(&z, &mut self.masking[0..4]);
        z_to_x(&z, &mut x);
        extract_b(&x, &mut self.masking[4..8]);
        x_to_z(&x, &mut z);
        extract_c(&z, &mut self.masking[8..12]);
        z_to_x(&z, &mut x);
        extract_d(&x, &mut self.masking[12..16]);

        x_to_z(&x, &mut z);
        extract_a(&z, &mut self.rotations[0..4]);
        z_to_x(&z, &mut x);
        extract_b(&x, &mut self.rotations[4..8]);
        x_to_z(&x, &mut z);
        extract_c(&z, &mut self.rotations[8..12]);
        z_to_x(&z, &mut x);
        extract_d(&x, &mut self.rotations[12..16]);
        for rotation in &mut self.rotations {
            *rotation &= 0x1f;
        }
    }

    pub(super) fn encrypt_block(
        &self,
        input: &[u8; CAST5_BLOCK_BYTES],
        output: &mut [u8; CAST5_BLOCK_BYTES],
    ) {
        let left = u32::from_be_bytes(input[..4].try_into().unwrap());
        let right = u32::from_be_bytes(input[4..].try_into().unwrap());
        let (left, right) = self.encipher(left, right);
        output[..4].copy_from_slice(&left.to_be_bytes());
        output[4..].copy_from_slice(&right.to_be_bytes());
    }

    pub(super) fn decrypt_block(
        &self,
        input: &[u8; CAST5_BLOCK_BYTES],
        output: &mut [u8; CAST5_BLOCK_BYTES],
    ) {
        let left = u32::from_be_bytes(input[..4].try_into().unwrap());
        let right = u32::from_be_bytes(input[4..].try_into().unwrap());
        let (left, right) = self.decipher(left, right);
        output[..4].copy_from_slice(&left.to_be_bytes());
        output[4..].copy_from_slice(&right.to_be_bytes());
    }

    fn encipher(&self, mut left: u32, mut right: u32) -> (u32, u32) {
        for round in 0..self.rounds {
            let next = left ^ self.round_function(round, right);
            left = right;
            right = next;
        }
        (right, left)
    }

    fn decipher(&self, mut left: u32, mut right: u32) -> (u32, u32) {
        for round in (0..self.rounds).rev() {
            let next = left ^ self.round_function(round, right);
            left = right;
            right = next;
        }
        (right, left)
    }

    #[inline]
    fn round_function(&self, round: usize, data: u32) -> u32 {
        match round % 3 {
            0 => f1(data, self.masking[round], self.rotations[round]),
            1 => f2(data, self.masking[round], self.rotations[round]),
            _ => f3(data, self.masking[round], self.rotations[round]),
        }
    }
}

fn read_word(bytes: &[u8; 16], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn write_word(value: u32, bytes: &mut [u8; 16], offset: usize) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn x_to_z(x: &[u8; 16], z: &mut [u8; 16]) {
    let x03 = read_word(x, 0);
    let x47 = read_word(x, 4);
    let x8b = read_word(x, 8);
    let xcf = read_word(x, 12);

    let z03 = x03
        ^ S5[x[13] as usize]
        ^ S6[x[15] as usize]
        ^ S7[x[12] as usize]
        ^ S8[x[14] as usize]
        ^ S7[x[8] as usize];
    write_word(z03, z, 0);
    let z47 = x8b
        ^ S5[z[0] as usize]
        ^ S6[z[2] as usize]
        ^ S7[z[1] as usize]
        ^ S8[z[3] as usize]
        ^ S8[x[10] as usize];
    write_word(z47, z, 4);
    let z8b = xcf
        ^ S5[z[7] as usize]
        ^ S6[z[6] as usize]
        ^ S7[z[5] as usize]
        ^ S8[z[4] as usize]
        ^ S5[x[9] as usize];
    write_word(z8b, z, 8);
    let zcf = x47
        ^ S5[z[10] as usize]
        ^ S6[z[9] as usize]
        ^ S7[z[11] as usize]
        ^ S8[z[8] as usize]
        ^ S6[x[11] as usize];
    write_word(zcf, z, 12);
}

fn z_to_x(z: &[u8; 16], x: &mut [u8; 16]) {
    let z03 = read_word(z, 0);
    let z47 = read_word(z, 4);
    let z8b = read_word(z, 8);
    let zcf = read_word(z, 12);

    let x03 = z8b
        ^ S5[z[5] as usize]
        ^ S6[z[7] as usize]
        ^ S7[z[4] as usize]
        ^ S8[z[6] as usize]
        ^ S7[z[0] as usize];
    write_word(x03, x, 0);
    let x47 = z03
        ^ S5[x[0] as usize]
        ^ S6[x[2] as usize]
        ^ S7[x[1] as usize]
        ^ S8[x[3] as usize]
        ^ S8[z[2] as usize];
    write_word(x47, x, 4);
    let x8b = z47
        ^ S5[x[7] as usize]
        ^ S6[x[6] as usize]
        ^ S7[x[5] as usize]
        ^ S8[x[4] as usize]
        ^ S5[z[1] as usize];
    write_word(x8b, x, 8);
    let xcf = zcf
        ^ S5[x[10] as usize]
        ^ S6[x[9] as usize]
        ^ S7[x[11] as usize]
        ^ S8[x[8] as usize]
        ^ S6[z[3] as usize];
    write_word(xcf, x, 12);
}

fn extract_a(bytes: &[u8; 16], output: &mut [u32]) {
    output[0] = S5[bytes[8] as usize]
        ^ S6[bytes[9] as usize]
        ^ S7[bytes[7] as usize]
        ^ S8[bytes[6] as usize]
        ^ S5[bytes[2] as usize];
    output[1] = S5[bytes[10] as usize]
        ^ S6[bytes[11] as usize]
        ^ S7[bytes[5] as usize]
        ^ S8[bytes[4] as usize]
        ^ S6[bytes[6] as usize];
    output[2] = S5[bytes[12] as usize]
        ^ S6[bytes[13] as usize]
        ^ S7[bytes[3] as usize]
        ^ S8[bytes[2] as usize]
        ^ S7[bytes[9] as usize];
    output[3] = S5[bytes[14] as usize]
        ^ S6[bytes[15] as usize]
        ^ S7[bytes[1] as usize]
        ^ S8[bytes[0] as usize]
        ^ S8[bytes[12] as usize];
}

fn extract_b(bytes: &[u8; 16], output: &mut [u32]) {
    output[0] = S5[bytes[3] as usize]
        ^ S6[bytes[2] as usize]
        ^ S7[bytes[12] as usize]
        ^ S8[bytes[13] as usize]
        ^ S5[bytes[8] as usize];
    output[1] = S5[bytes[1] as usize]
        ^ S6[bytes[0] as usize]
        ^ S7[bytes[14] as usize]
        ^ S8[bytes[15] as usize]
        ^ S6[bytes[13] as usize];
    output[2] = S5[bytes[7] as usize]
        ^ S6[bytes[6] as usize]
        ^ S7[bytes[8] as usize]
        ^ S8[bytes[9] as usize]
        ^ S7[bytes[3] as usize];
    output[3] = S5[bytes[5] as usize]
        ^ S6[bytes[4] as usize]
        ^ S7[bytes[10] as usize]
        ^ S8[bytes[11] as usize]
        ^ S8[bytes[7] as usize];
}

fn extract_c(bytes: &[u8; 16], output: &mut [u32]) {
    output[0] = S5[bytes[3] as usize]
        ^ S6[bytes[2] as usize]
        ^ S7[bytes[12] as usize]
        ^ S8[bytes[13] as usize]
        ^ S5[bytes[9] as usize];
    output[1] = S5[bytes[1] as usize]
        ^ S6[bytes[0] as usize]
        ^ S7[bytes[14] as usize]
        ^ S8[bytes[15] as usize]
        ^ S6[bytes[12] as usize];
    output[2] = S5[bytes[7] as usize]
        ^ S6[bytes[6] as usize]
        ^ S7[bytes[8] as usize]
        ^ S8[bytes[9] as usize]
        ^ S7[bytes[2] as usize];
    output[3] = S5[bytes[5] as usize]
        ^ S6[bytes[4] as usize]
        ^ S7[bytes[10] as usize]
        ^ S8[bytes[11] as usize]
        ^ S8[bytes[6] as usize];
}

fn extract_d(bytes: &[u8; 16], output: &mut [u32]) {
    output[0] = S5[bytes[8] as usize]
        ^ S6[bytes[9] as usize]
        ^ S7[bytes[7] as usize]
        ^ S8[bytes[6] as usize]
        ^ S5[bytes[3] as usize];
    output[1] = S5[bytes[10] as usize]
        ^ S6[bytes[11] as usize]
        ^ S7[bytes[5] as usize]
        ^ S8[bytes[4] as usize]
        ^ S6[bytes[7] as usize];
    output[2] = S5[bytes[12] as usize]
        ^ S6[bytes[13] as usize]
        ^ S7[bytes[3] as usize]
        ^ S8[bytes[2] as usize]
        ^ S7[bytes[8] as usize];
    output[3] = S5[bytes[14] as usize]
        ^ S6[bytes[15] as usize]
        ^ S7[bytes[1] as usize]
        ^ S8[bytes[0] as usize]
        ^ S8[bytes[13] as usize];
}
