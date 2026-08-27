//! GOST 28147 block-cipher engine.

use tc_crypto_core::BlockCipher;

use super::{
    GOST28147_BLOCK_BYTES, GOST28147_S_BOX_BYTES, Gost28147Error, Gost28147Params, Gost28147SBox,
};

/// GOST 28147-89 with a 256-bit key and 64-bit block.
pub struct Gost28147Engine {
    working_key: [u32; 8],
    s_box: [u8; GOST28147_S_BOX_BYTES],
    for_encryption: bool,
    initialised: bool,
}

impl Gost28147Engine {
    /// Creates an uninitialised engine with the default S-box.
    pub fn new() -> Self {
        Self {
            working_key: [0; 8],
            s_box: *Gost28147SBox::Default.table(),
            for_encryption: false,
            initialised: false,
        }
    }

    fn main_step(&self, n1: u32, key: u32) -> u32 {
        let cm = n1.wrapping_add(key);
        let mut substituted = 0u32;
        for row in 0..8 {
            let nibble = ((cm >> (row * 4)) & 0xF) as usize;
            substituted |= (self.s_box[row * 16 + nibble] as u32) << (row * 4);
        }
        substituted.rotate_left(11)
    }

    fn round(&self, n1: &mut u32, n2: &mut u32, key_index: usize) {
        let old_n1 = *n1;
        *n1 = *n2 ^ self.main_step(*n1, self.working_key[key_index]);
        *n2 = old_n1;
    }

    fn transform(&self, input: &[u8], output: &mut [u8]) {
        let mut n1 = u32::from_le_bytes(input[..4].try_into().unwrap());
        let mut n2 = u32::from_le_bytes(input[4..8].try_into().unwrap());

        if self.for_encryption {
            for _ in 0..3 {
                for key_index in 0..8 {
                    self.round(&mut n1, &mut n2, key_index);
                }
            }
            for key_index in (1..8).rev() {
                self.round(&mut n1, &mut n2, key_index);
            }
        } else {
            for key_index in 0..8 {
                self.round(&mut n1, &mut n2, key_index);
            }
            for cycle in 0..3 {
                for key_index in (0..8).rev() {
                    if cycle == 2 && key_index == 0 {
                        break;
                    }
                    self.round(&mut n1, &mut n2, key_index);
                }
            }
        }

        n2 ^= self.main_step(n1, self.working_key[0]);
        output[..4].copy_from_slice(&n1.to_le_bytes());
        output[4..8].copy_from_slice(&n2.to_le_bytes());
    }
}

impl Default for Gost28147Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockCipher for Gost28147Engine {
    type Params<'a> = Gost28147Params;
    type Error = Gost28147Error;

    fn algorithm_name(&self) -> &str {
        "Gost28147"
    }

    fn block_size(&self) -> usize {
        GOST28147_BLOCK_BYTES
    }

    fn init(&mut self, for_encryption: bool, params: &Self::Params<'_>) -> Result<(), Self::Error> {
        for (word, bytes) in self
            .working_key
            .iter_mut()
            .zip(params.key().chunks_exact(4))
        {
            *word = u32::from_le_bytes(bytes.try_into().unwrap());
        }
        self.s_box.copy_from_slice(params.s_box());
        self.for_encryption = for_encryption;
        self.initialised = true;
        Ok(())
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(Gost28147Error::NotInitialised);
        }
        if input.len() < GOST28147_BLOCK_BYTES || output.len() < GOST28147_BLOCK_BYTES {
            return Err(Gost28147Error::BufferTooShort);
        }
        self.transform(input, output);
        Ok(GOST28147_BLOCK_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accessors_and_pre_init_errors() {
        let mut engine = Gost28147Engine::new();
        assert_eq!(engine.algorithm_name(), "Gost28147");
        assert_eq!(engine.block_size(), 8);
        assert_eq!(
            engine.process_block(&[0u8; 8], &mut [0u8; 8]),
            Err(Gost28147Error::NotInitialised)
        );
    }

    #[test]
    fn short_buffers_are_rejected() {
        let key = [0u8; 32];
        let params = Gost28147Params::new(&key).unwrap();
        let mut engine = Gost28147Engine::new();
        engine.init(true, &params).unwrap();
        assert_eq!(
            engine.process_block(&[0u8; 7], &mut [0u8; 8]),
            Err(Gost28147Error::BufferTooShort)
        );
        assert_eq!(
            engine.process_block(&[0u8; 8], &mut [0u8; 7]),
            Err(Gost28147Error::BufferTooShort)
        );
    }
}
