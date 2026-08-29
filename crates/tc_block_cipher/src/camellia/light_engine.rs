//! Small-footprint Camellia block-cipher engine.

use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};

use super::{BlockCipherError, CAMELLIA_BLOCK_BYTES, CamelliaParams, cipher};

const SBOX1: [u8; 256] = [
    112, 130, 44, 236, 179, 39, 192, 229, 228, 133, 87, 53, 234, 12, 174, 65, 35, 239, 107, 147,
    69, 25, 165, 33, 237, 14, 79, 78, 29, 101, 146, 189, 134, 184, 175, 143, 124, 235, 31, 206, 62,
    48, 220, 95, 94, 197, 11, 26, 166, 225, 57, 202, 213, 71, 93, 61, 217, 1, 90, 214, 81, 86, 108,
    77, 139, 13, 154, 102, 251, 204, 176, 45, 116, 18, 43, 32, 240, 177, 132, 153, 223, 76, 203,
    194, 52, 126, 118, 5, 109, 183, 169, 49, 209, 23, 4, 215, 20, 88, 58, 97, 222, 27, 17, 28, 50,
    15, 156, 22, 83, 24, 242, 34, 254, 68, 207, 178, 195, 181, 122, 145, 36, 8, 232, 168, 96, 252,
    105, 80, 170, 208, 160, 125, 161, 137, 98, 151, 84, 91, 30, 149, 224, 255, 100, 210, 16, 196,
    0, 72, 163, 247, 117, 219, 138, 3, 230, 218, 9, 63, 221, 148, 135, 92, 131, 2, 205, 74, 144,
    51, 115, 103, 246, 243, 157, 127, 191, 226, 82, 155, 216, 38, 200, 55, 198, 59, 129, 150, 111,
    75, 19, 190, 99, 46, 233, 121, 167, 140, 159, 110, 188, 142, 41, 245, 249, 182, 47, 253, 180,
    89, 120, 152, 6, 106, 231, 70, 113, 186, 212, 37, 171, 66, 136, 162, 141, 250, 114, 7, 185, 85,
    248, 238, 172, 10, 54, 73, 42, 104, 60, 56, 241, 164, 64, 40, 211, 123, 187, 201, 67, 193, 21,
    227, 173, 244, 119, 199, 128, 158,
];

#[inline]
fn sbox2(value: u8) -> u32 {
    SBOX1[value as usize].rotate_left(1) as u32
}

#[inline]
fn sbox3(value: u8) -> u32 {
    SBOX1[value as usize].rotate_left(7) as u32
}

#[inline]
fn sbox4(value: u8) -> u32 {
    SBOX1[value.rotate_left(1) as usize] as u32
}

fn camellia_f2_light(state: &mut [u32; 4], subkey: &[u32], key_offset: usize) {
    let first = state[0] ^ subkey[key_offset];
    let mut u = sbox4(first as u8)
        | (sbox3((first >> 8) as u8) << 8)
        | (sbox2((first >> 16) as u8) << 16)
        | ((SBOX1[(first >> 24) as usize] as u32) << 24);

    let second = state[1] ^ subkey[key_offset + 1];
    let mut v = SBOX1[second as u8 as usize] as u32
        | (sbox4((second >> 8) as u8) << 8)
        | (sbox3((second >> 16) as u8) << 16)
        | (sbox2((second >> 24) as u8) << 24);

    v = v.rotate_left(8);
    u ^= v;
    v = v.rotate_left(8) ^ u;
    u = u.rotate_right(8) ^ v;
    state[2] ^= v.rotate_left(16) ^ u;
    state[3] ^= u.rotate_left(8);

    let first = state[2] ^ subkey[key_offset + 2];
    let mut u = sbox4(first as u8)
        | (sbox3((first >> 8) as u8) << 8)
        | (sbox2((first >> 16) as u8) << 16)
        | ((SBOX1[(first >> 24) as usize] as u32) << 24);

    let second = state[3] ^ subkey[key_offset + 3];
    let mut v = SBOX1[second as u8 as usize] as u32
        | (sbox4((second >> 8) as u8) << 8)
        | (sbox3((second >> 16) as u8) << 16)
        | (sbox2((second >> 24) as u8) << 24);

    v = v.rotate_left(8);
    u ^= v;
    v = v.rotate_left(8) ^ u;
    u = u.rotate_right(8) ^ v;
    state[0] ^= v.rotate_left(16) ^ u;
    state[1] ^= u.rotate_left(8);
}

/// Camellia using one 256-byte S-box and computed S-box transforms.
///
/// This corresponds to Bouncy Castle's `CamelliaLightEngine`. It shares the
/// Camellia key schedule with [`super::CamelliaEngine`] but does not use that
/// engine's four 256-entry `u32` T-tables.
pub struct CamelliaLightEngine {
    schedule: cipher::CamelliaKeySchedule,
    initialised: bool,
}

impl CamelliaLightEngine {
    /// Creates an uninitialised light Camellia engine.
    pub const fn new() -> Self {
        Self {
            schedule: cipher::CamelliaKeySchedule::new(),
            initialised: false,
        }
    }
}

impl Default for CamelliaLightEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockCipher for CamelliaLightEngine {
    type Error = BlockCipherError;

    fn algorithm_name(&self) -> &str {
        "Camellia"
    }

    fn block_size(&self) -> usize {
        CAMELLIA_BLOCK_BYTES
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BlockCipherError::NotInitialised);
        }
        if input.len() < CAMELLIA_BLOCK_BYTES || output.len() < CAMELLIA_BLOCK_BYTES {
            return Err(BlockCipherError::BufferTooShort);
        }

        let input: &[u8; CAMELLIA_BLOCK_BYTES] = input[..CAMELLIA_BLOCK_BYTES].try_into().unwrap();
        let output: &mut [u8; CAMELLIA_BLOCK_BYTES] =
            (&mut output[..CAMELLIA_BLOCK_BYTES]).try_into().unwrap();
        self.schedule
            .process_block_with(input, output, camellia_f2_light);
        Ok(CAMELLIA_BLOCK_BYTES)
    }
}

impl BlockCipherInit for CamelliaLightEngine {
    type Params<'a> = CamelliaParams;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        self.schedule.set_key_with(
            direction == CipherDirection::Encrypt,
            params.key(),
            camellia_f2_light,
        );
        self.initialised = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accessors_and_processing_errors() {
        let mut engine = CamelliaLightEngine::new();
        assert_eq!(engine.algorithm_name(), "Camellia");
        assert_eq!(engine.block_size(), CAMELLIA_BLOCK_BYTES);
        assert_eq!(
            engine.process_block(&[0u8; 16], &mut [0u8; 16]),
            Err(BlockCipherError::NotInitialised)
        );

        engine
            .init(
                CipherDirection::Encrypt,
                &CamelliaParams::new(&[0u8; 16]).unwrap(),
            )
            .unwrap();
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
