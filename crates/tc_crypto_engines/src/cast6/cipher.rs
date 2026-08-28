//! CAST6 key schedule and block transformation.

use crate::cast_common::{f1, f2, f3};

use super::CAST6_BLOCK_BYTES;

const QUAD_ROUNDS: usize = 12;
const SUBKEYS_PER_ROUND: usize = 4;
const SUBKEY_COUNT: usize = QUAD_ROUNDS * SUBKEYS_PER_ROUND;

pub(super) struct Cast6KeySchedule {
    masking: [u32; SUBKEY_COUNT],
    rotations: [u32; SUBKEY_COUNT],
}

impl Cast6KeySchedule {
    pub(super) const fn new() -> Self {
        Self {
            masking: [0; SUBKEY_COUNT],
            rotations: [0; SUBKEY_COUNT],
        }
    }

    pub(super) fn set_key(&mut self, key: &[u8]) {
        self.masking = [0; SUBKEY_COUNT];
        self.rotations = [0; SUBKEY_COUNT];

        let mut padded = [0u8; 32];
        padded[..key.len()].copy_from_slice(key);
        let mut working = [0u32; 8];
        for (index, chunk) in padded.chunks_exact(4).enumerate() {
            working[index] = u32::from_be_bytes(chunk.try_into().unwrap());
        }

        let mut mask_constant = 0x5a82_7999u32;
        let mut rotation_constant = 19u32;
        for round in 0..QUAD_ROUNDS {
            key_schedule_octave(&mut working, &mut mask_constant, &mut rotation_constant);
            key_schedule_octave(&mut working, &mut mask_constant, &mut rotation_constant);

            let offset = round * SUBKEYS_PER_ROUND;
            self.rotations[offset] = working[0] & 0x1f;
            self.rotations[offset + 1] = working[2] & 0x1f;
            self.rotations[offset + 2] = working[4] & 0x1f;
            self.rotations[offset + 3] = working[6] & 0x1f;
            self.masking[offset] = working[7];
            self.masking[offset + 1] = working[5];
            self.masking[offset + 2] = working[3];
            self.masking[offset + 3] = working[1];
        }
    }

    pub(super) fn encrypt_block(
        &self,
        input: &[u8; CAST6_BLOCK_BYTES],
        output: &mut [u8; CAST6_BLOCK_BYTES],
    ) {
        let mut state = read_state(input);

        for round in 0..6 {
            self.q(&mut state, round);
        }
        for round in 6..QUAD_ROUNDS {
            self.q_bar(&mut state, round);
        }

        write_state(&state, output);
    }

    pub(super) fn decrypt_block(
        &self,
        input: &[u8; CAST6_BLOCK_BYTES],
        output: &mut [u8; CAST6_BLOCK_BYTES],
    ) {
        let mut state = read_state(input);

        for round in (6..QUAD_ROUNDS).rev() {
            self.q(&mut state, round);
        }
        for round in (0..6).rev() {
            self.q_bar(&mut state, round);
        }

        write_state(&state, output);
    }

    #[inline]
    fn q(&self, state: &mut [u32; 4], round: usize) {
        let offset = round * SUBKEYS_PER_ROUND;
        state[2] ^= f1(state[3], self.masking[offset], self.rotations[offset]);
        state[1] ^= f2(
            state[2],
            self.masking[offset + 1],
            self.rotations[offset + 1],
        );
        state[0] ^= f3(
            state[1],
            self.masking[offset + 2],
            self.rotations[offset + 2],
        );
        state[3] ^= f1(
            state[0],
            self.masking[offset + 3],
            self.rotations[offset + 3],
        );
    }

    #[inline]
    fn q_bar(&self, state: &mut [u32; 4], round: usize) {
        let offset = round * SUBKEYS_PER_ROUND;
        state[3] ^= f1(
            state[0],
            self.masking[offset + 3],
            self.rotations[offset + 3],
        );
        state[0] ^= f3(
            state[1],
            self.masking[offset + 2],
            self.rotations[offset + 2],
        );
        state[1] ^= f2(
            state[2],
            self.masking[offset + 1],
            self.rotations[offset + 1],
        );
        state[2] ^= f1(state[3], self.masking[offset], self.rotations[offset]);
    }
}

fn key_schedule_octave(
    working: &mut [u32; 8],
    mask_constant: &mut u32,
    rotation_constant: &mut u32,
) {
    working[6] ^= f1(working[7], *mask_constant, *rotation_constant);
    advance_constants(mask_constant, rotation_constant);
    working[5] ^= f2(working[6], *mask_constant, *rotation_constant);
    advance_constants(mask_constant, rotation_constant);
    working[4] ^= f3(working[5], *mask_constant, *rotation_constant);
    advance_constants(mask_constant, rotation_constant);
    working[3] ^= f1(working[4], *mask_constant, *rotation_constant);
    advance_constants(mask_constant, rotation_constant);
    working[2] ^= f2(working[3], *mask_constant, *rotation_constant);
    advance_constants(mask_constant, rotation_constant);
    working[1] ^= f3(working[2], *mask_constant, *rotation_constant);
    advance_constants(mask_constant, rotation_constant);
    working[0] ^= f1(working[1], *mask_constant, *rotation_constant);
    advance_constants(mask_constant, rotation_constant);
    working[7] ^= f2(working[0], *mask_constant, *rotation_constant);
    advance_constants(mask_constant, rotation_constant);
}

#[inline]
fn advance_constants(mask_constant: &mut u32, rotation_constant: &mut u32) {
    *mask_constant = mask_constant.wrapping_add(0x6ed9_eba1);
    *rotation_constant = rotation_constant.wrapping_add(17) & 0x1f;
}

fn read_state(input: &[u8; CAST6_BLOCK_BYTES]) -> [u32; 4] {
    core::array::from_fn(|index| {
        u32::from_be_bytes(input[index * 4..index * 4 + 4].try_into().unwrap())
    })
}

fn write_state(state: &[u32; 4], output: &mut [u8; CAST6_BLOCK_BYTES]) {
    for (index, value) in state.iter().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&value.to_be_bytes());
    }
}
