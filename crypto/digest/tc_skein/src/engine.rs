//! Skein's Unique Block Iteration engine.

use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_threefish::{Params, ThreefishEngine};

use crate::{SKEIN_256, SKEIN_512, SKEIN_1024};

const MAX_WORDS: usize = 16;
const MAX_BLOCK_BYTES: usize = MAX_WORDS * 8;
const TYPE_CONFIG: u8 = 4;
const TYPE_MESSAGE: u8 = 48;
const TYPE_OUTPUT: u8 = 63;
const T1_FIRST: u64 = 1 << 62;
const T1_FINAL: u64 = 1 << 63;

#[derive(Clone, Copy)]
struct UbiTweak([u64; 2]);

impl UbiTweak {
    fn new(block_type: u8) -> Self {
        Self([0, T1_FIRST | ((block_type as u64 & 0x3f) << 56)])
    }

    fn advance(&mut self, amount: usize) {
        // Bits 0..95 form a little-endian position. Adding through three
        // 32-bit limbs avoids a special overflow path.
        let mut limbs = [
            self.0[0] & 0xffff_ffff,
            self.0[0] >> 32,
            self.0[1] & 0xffff_ffff,
        ];
        let mut carry = amount as u64;
        for limb in &mut limbs {
            carry += *limb;
            *limb = carry & 0xffff_ffff;
            carry >>= 32;
        }
        self.0[0] = limbs[0] | (limbs[1] << 32);
        self.0[1] = (self.0[1] & 0xffff_ffff_0000_0000) | limbs[2];
    }

    fn clear_first(&mut self) {
        self.0[1] &= !T1_FIRST;
    }

    fn set_final(&mut self) {
        self.0[1] |= T1_FINAL;
    }
}

/// Reusable Skein 1.3 UBI engine for unkeyed digest operation.
///
/// It owns Skein's chaining state, configuration, streaming buffer, tweak, and
/// output transform while delegating every block encryption to `tc_threefish`.
#[derive(Clone)]
pub struct SkeinEngine {
    state_bits: usize,
    output_bits: usize,
    words: usize,
    chain: [u64; MAX_WORDS],
    initial_state: [u64; MAX_WORDS],
    block: [u8; MAX_BLOCK_BYTES],
    block_offset: usize,
    tweak: UbiTweak,
}

impl SkeinEngine {
    /// Creates an unkeyed Skein engine.
    ///
    /// `state_size_bits` must be 256, 512, or 1024. The output size must be a
    /// positive multiple of eight bits.
    pub fn new(state_size_bits: usize, output_size_bits: usize) -> Self {
        assert!(
            matches!(state_size_bits, SKEIN_256 | SKEIN_512 | SKEIN_1024),
            "Skein state size must be 256, 512, or 1024 bits"
        );
        assert!(
            output_size_bits > 0 && output_size_bits.is_multiple_of(8),
            "Skein output size must be a positive multiple of 8 bits"
        );

        let words = state_size_bits / 64;
        let mut engine = Self {
            state_bits: state_size_bits,
            output_bits: output_size_bits,
            words,
            chain: [0; MAX_WORDS],
            initial_state: [0; MAX_WORDS],
            block: [0; MAX_BLOCK_BYTES],
            block_offset: 0,
            tweak: UbiTweak::new(TYPE_CONFIG),
        };

        let mut config = [0u8; 32];
        config[..4].copy_from_slice(b"SHA3");
        config[4..6].copy_from_slice(&1u16.to_le_bytes());
        config[8..16].copy_from_slice(&(output_size_bits as u64).to_le_bytes());
        engine.ubi_complete(TYPE_CONFIG, &config);
        engine.initial_state = engine.chain;
        engine.ubi_init(TYPE_MESSAGE);
        engine
    }

    /// Returns the internal state/block size in bytes.
    pub const fn block_size(&self) -> usize {
        self.state_bits / 8
    }

    /// Returns the configured output size in bytes.
    pub const fn output_size(&self) -> usize {
        self.output_bits / 8
    }

    /// Absorbs message bytes.
    pub fn update(&mut self, mut input: &[u8]) {
        let block_size = self.block_size();
        while !input.is_empty() {
            // Keep the last complete block buffered so it receives FINAL when
            // no later input follows.
            if self.block_offset == block_size {
                self.process_buffered_block();
                self.tweak.clear_first();
                self.block_offset = 0;
            }
            let take = core::cmp::min(input.len(), block_size - self.block_offset);
            self.block[self.block_offset..self.block_offset + take].copy_from_slice(&input[..take]);
            self.block_offset += take;
            self.tweak.advance(take);
            input = &input[take..];
        }
    }

    /// Finalizes into `output`, then resets the engine for another message.
    pub fn do_final(&mut self, output: &mut [u8]) -> usize {
        let output_size = self.output_size();
        assert!(
            output.len() >= output_size,
            "Skein output buffer is too short"
        );

        let block_size = self.block_size();
        self.block[self.block_offset..block_size].fill(0);
        self.tweak.set_final();
        self.process_buffered_block();

        let final_chain = self.chain;
        for (sequence, chunk) in output[..output_size].chunks_mut(block_size).enumerate() {
            let counter = (sequence as u64).to_le_bytes();
            let words = self.ubi_one_shot(&final_chain, TYPE_OUTPUT, &counter);
            write_words(&words, self.words, chunk);
        }

        self.reset();
        output_size
    }

    /// Restores the configured initial state and starts a new message UBI.
    pub fn reset(&mut self) {
        self.chain = self.initial_state;
        self.block.fill(0);
        self.ubi_init(TYPE_MESSAGE);
    }

    fn ubi_init(&mut self, block_type: u8) {
        self.tweak = UbiTweak::new(block_type);
        self.block_offset = 0;
    }

    fn ubi_complete(&mut self, block_type: u8, input: &[u8]) {
        self.ubi_init(block_type);
        self.update(input);
        let block_size = self.block_size();
        self.block[self.block_offset..block_size].fill(0);
        self.tweak.set_final();
        self.process_buffered_block();
    }

    fn process_buffered_block(&mut self) {
        let key = self.chain;
        self.chain = self.encrypt_ubi(&key, &self.block, self.tweak);
    }

    fn ubi_one_shot(
        &self,
        key: &[u64; MAX_WORDS],
        block_type: u8,
        input: &[u8],
    ) -> [u64; MAX_WORDS] {
        debug_assert!(input.len() <= self.block_size());
        let mut block = [0u8; MAX_BLOCK_BYTES];
        block[..input.len()].copy_from_slice(input);
        let mut tweak = UbiTweak::new(block_type);
        tweak.advance(input.len());
        tweak.set_final();
        self.encrypt_ubi(key, &block, tweak)
    }

    fn encrypt_ubi(
        &self,
        key_words: &[u64; MAX_WORDS],
        message: &[u8; MAX_BLOCK_BYTES],
        tweak: UbiTweak,
    ) -> [u64; MAX_WORDS] {
        let block_size = self.block_size();
        let mut key = [0u8; MAX_BLOCK_BYTES];
        write_words(key_words, self.words, &mut key[..block_size]);
        let mut tweak_bytes = [0u8; 16];
        tweak_bytes[..8].copy_from_slice(&tweak.0[0].to_le_bytes());
        tweak_bytes[8..].copy_from_slice(&tweak.0[1].to_le_bytes());
        let params = Params::with_tweak(&key[..block_size], &tweak_bytes);
        let mut encrypted = [0u8; MAX_BLOCK_BYTES];

        match self.words {
            4 => process_threefish::<4>(&params, message, &mut encrypted),
            8 => process_threefish::<8>(&params, message, &mut encrypted),
            16 => process_threefish::<16>(&params, message, &mut encrypted),
            _ => unreachable!("Skein validates its state size"),
        }

        let mut output = [0u64; MAX_WORDS];
        for (index, word) in output[..self.words].iter_mut().enumerate() {
            let offset = index * 8;
            *word = u64::from_le_bytes(encrypted[offset..offset + 8].try_into().unwrap())
                ^ u64::from_le_bytes(message[offset..offset + 8].try_into().unwrap());
        }
        output
    }
}

fn process_threefish<const WORDS: usize>(
    params: &Params<'_>,
    input: &[u8; MAX_BLOCK_BYTES],
    output: &mut [u8; MAX_BLOCK_BYTES],
) {
    let mut cipher = ThreefishEngine::<WORDS>::new();
    cipher
        .init(CipherDirection::Encrypt, params)
        .expect("Skein always supplies a full Threefish key and tweak");
    cipher
        .process_block(input, output)
        .expect("Skein always supplies a full Threefish block");
}

fn write_words(words: &[u64; MAX_WORDS], count: usize, output: &mut [u8]) {
    for (word, bytes) in words[..count].iter().zip(output.chunks_mut(8)) {
        let encoded = word.to_le_bytes();
        bytes.copy_from_slice(&encoded[..bytes.len()]);
    }
}
