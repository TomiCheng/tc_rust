//! Pieces the engines share: the field arithmetic, the S-box and its inverse,
//! the round count for each key length, and a constant-time key expansion.

use tc_zeroize::Zeroize;

use crate::BLOCK_BYTES;

/// Multiplication in GF(2^8) modulo the AES polynomial. Constant time.
pub(crate) const fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    let mut index = 0;
    while index < 8 {
        product ^= a & 0u8.wrapping_sub(b & 1);
        let high_bit = a >> 7;
        a = (a << 1) ^ (0x1B & 0u8.wrapping_sub(high_bit));
        b >>= 1;
        index += 1;
    }
    product
}

/// `value` to a public power. Branches only on the exponent.
const fn gf_pow(mut value: u8, mut exponent: u8) -> u8 {
    let mut result = 1u8;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = gf_mul(result, value);
        }
        value = gf_mul(value, value);
        exponent >>= 1;
    }
    result
}

/// The S-box entry for `value`: its inverse in GF(2^8), with 0 mapping to 0,
/// through the affine map. Constant time: arithmetic only, no table.
pub(crate) const fn s_box_value(value: u8) -> u8 {
    // value^254 is the inverse, and 0^254 is 0, so zero needs no branch.
    let inverse = gf_pow(value, 254);
    inverse
        ^ inverse.rotate_left(1)
        ^ inverse.rotate_left(2)
        ^ inverse.rotate_left(3)
        ^ inverse.rotate_left(4)
        ^ 0x63
}

const fn build_s_box() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut index = 0;
    while index < 256 {
        table[index] = s_box_value(index as u8);
        index += 1;
    }
    table
}

const fn build_inverse_s_box() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut index = 0;
    while index < 256 {
        table[S_BOX[index] as usize] = index as u8;
        index += 1;
    }
    table
}

/// Computed at compile time from the field arithmetic, not copied from a table.
pub(crate) const S_BOX: [u8; 256] = build_s_box();
pub(crate) const INVERSE_S_BOX: [u8; 256] = build_inverse_s_box();

/// Rounds for a key length in bytes, or `None` if AES defines none.
pub(crate) const fn rounds_for(key_len: usize) -> Option<usize> {
    match key_len {
        16 => Some(10),
        24 => Some(12),
        32 => Some(14),
        _ => None,
    }
}

/// Round keys for the longest schedule: AES-256's fourteen rounds plus the
/// initial whitening key.
pub(crate) const MAX_ROUND_KEYS: usize = 15;
/// The expanded key, one block per round.
pub(crate) type RoundKeys = [[u8; BLOCK_BYTES]; MAX_ROUND_KEYS];

#[inline]
const fn xtime(value: u8) -> u8 {
    (value << 1) ^ (0x1b & 0u8.wrapping_sub(value >> 7))
}

/// FIPS 197 §5.2 key expansion; `rounds` comes from [`rounds_for`]. Constant
/// time in the key: SubWord is computed with [`s_box_value`] rather than
/// looked up, and the branches follow only the key length and the position.
/// The working copies are wiped before returning.
pub(crate) fn expand_key(key: &[u8], rounds: usize) -> RoundKeys {
    let key_len = key.len();
    let expanded_len = BLOCK_BYTES * (rounds + 1);
    let mut expanded = [0u8; BLOCK_BYTES * MAX_ROUND_KEYS];
    expanded[..key_len].copy_from_slice(key);

    let mut generated = key_len;
    let mut rcon = 1u8;
    let mut temp = [0u8; 4];
    while generated < expanded_len {
        temp.copy_from_slice(&expanded[generated - 4..generated]);
        match generated % key_len {
            0 => {
                temp.rotate_left(1);
                temp = temp.map(s_box_value);
                temp[0] ^= rcon;
                rcon = xtime(rcon);
            }
            16 if key_len == 32 => temp = temp.map(s_box_value),
            _ => {}
        }
        for value in temp {
            expanded[generated] = expanded[generated - key_len] ^ value;
            generated += 1;
        }
    }

    let mut round_keys = [[0u8; BLOCK_BYTES]; MAX_ROUND_KEYS];
    for (round, round_key) in round_keys.iter_mut().enumerate().take(rounds + 1) {
        round_key.copy_from_slice(&expanded[round * BLOCK_BYTES..(round + 1) * BLOCK_BYTES]);
    }
    expanded.zeroize();
    temp.zeroize();
    round_keys
}

#[cfg(test)]
mod tests {
    use super::{INVERSE_S_BOX, S_BOX, expand_key, rounds_for, s_box_value};

    #[test]
    fn the_generated_s_boxes_have_the_standard_endpoints_and_invert_each_other() {
        assert_eq!(S_BOX[..4], [0x63, 0x7c, 0x77, 0x7b]);
        assert_eq!(S_BOX[252..], [0xb0, 0x54, 0xbb, 0x16]);
        for value in 0..=u8::MAX {
            assert_eq!(INVERSE_S_BOX[usize::from(S_BOX[usize::from(value)])], value);
        }
    }

    #[test]
    fn the_branchless_s_box_maps_zero_to_0x63() {
        assert_eq!(s_box_value(0), 0x63);
    }

    #[test]
    fn only_the_three_standard_key_lengths_have_rounds() {
        assert_eq!(rounds_for(16), Some(10));
        assert_eq!(rounds_for(24), Some(12));
        assert_eq!(rounds_for(32), Some(14));
        for key_len in [0, 8, 15, 17, 23, 25, 31, 33, 64] {
            assert_eq!(rounds_for(key_len), None, "key length {key_len}");
        }
    }

    #[test]
    fn key_expansion_matches_fips_197_appendix_a() {
        // A.1: the last round key of AES-128 under 2b7e1516 28aed2a6 abf71588 09cf4f3c.
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let round_keys = expand_key(&key, 10);
        assert_eq!(round_keys[0], key);
        assert_eq!(
            round_keys[10],
            [
                0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63,
                0x0c, 0xa6
            ]
        );
    }
}

/// FIPS 197 Appendix C and the checks every engine's tests share. Each check
/// takes the engine's constructor, so an engine without `Default` can use it.
#[cfg(test)]
pub(crate) mod test_support {
    use tc_block_cipher::{
        BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyRef,
    };

    /// What the checks need of an engine.
    pub(crate) trait Engine:
        for<'a> BlockCipherInit<KeyRef<'a>, Error = InitError> + BlockCipher<Error = BlockError>
    {
    }

    impl<T> Engine for T where
        T: for<'a> BlockCipherInit<KeyRef<'a>, Error = InitError> + BlockCipher<Error = BlockError>
    {
    }

    pub(crate) const PLAINTEXT: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    pub(crate) const CIPHERTEXT_128: [u8; 16] = [
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5,
        0x5a,
    ];
    pub(crate) const CIPHERTEXT_192: [u8; 16] = [
        0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71,
        0x91,
    ];
    pub(crate) const CIPHERTEXT_256: [u8; 16] = [
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60,
        0x89,
    ];

    /// The Appendix C key of `N` bytes: 00, 01, 02, ...
    pub(crate) fn key<const N: usize>() -> [u8; N] {
        core::array::from_fn(|i| i as u8)
    }

    pub(crate) fn keyed<E: Engine>(new: fn() -> E, direction: CipherDirection, key: &[u8]) -> E {
        let mut engine = new();
        engine.init(direction, &KeyRef::new(key)).unwrap();
        engine
    }

    pub(crate) fn process<E: Engine>(engine: &mut E, input: &[u8; 16]) -> [u8; 16] {
        let mut output = [0; 16];
        assert_eq!(engine.process_block(input, &mut output), Ok(16));
        output
    }

    pub(crate) fn check_fips_197<E: Engine>(new: fn() -> E) {
        let (key_128, key_192, key_256) = (key::<16>(), key::<24>(), key::<32>());
        let cases: [(&[u8], [u8; 16]); 3] = [
            (&key_128, CIPHERTEXT_128),
            (&key_192, CIPHERTEXT_192),
            (&key_256, CIPHERTEXT_256),
        ];
        for (key, ciphertext) in cases {
            let mut encryptor = keyed(new, CipherDirection::Encrypt, key);
            assert_eq!(
                process(&mut encryptor, &PLAINTEXT),
                ciphertext,
                "{}-byte key",
                key.len()
            );
            let mut decryptor = keyed(new, CipherDirection::Decrypt, key);
            assert_eq!(
                process(&mut decryptor, &ciphertext),
                PLAINTEXT,
                "{}-byte key",
                key.len()
            );
        }
    }

    pub(crate) fn check_uninitialised<E: Engine>(new: fn() -> E) {
        let mut engine = new();
        assert_eq!(engine.block_size(), 16);
        assert_eq!(
            engine.process_block(&[0; 16], &mut [0; 16]),
            Err(BlockError::NotInitialised)
        );
    }

    pub(crate) fn check_buffers<E: Engine>(new: fn() -> E) {
        let mut engine = keyed(new, CipherDirection::Encrypt, &key::<16>());
        assert_eq!(
            engine.process_block(&[0; 15], &mut [0; 16]),
            Err(BlockError::BufferTooShort)
        );
        assert_eq!(
            engine.process_block(&[0; 16], &mut [0; 15]),
            Err(BlockError::BufferTooShort)
        );

        let mut input = [0; 20];
        input[..16].copy_from_slice(&PLAINTEXT);
        let mut output = [0xaa; 20];
        assert_eq!(engine.process_block(&input, &mut output), Ok(16));
        assert_eq!(output[..16], CIPHERTEXT_128);
        assert_eq!(output[16..], [0xaa; 4]);
    }

    pub(crate) fn check_rejected_key<E: Engine>(new: fn() -> E) {
        let mut engine = keyed(new, CipherDirection::Decrypt, &key::<32>());
        let too_long = [0; 33];
        for len in [0, 15, 17, 23, 25, 31, 33] {
            assert_eq!(
                engine.init(CipherDirection::Encrypt, &KeyRef::new(&too_long[..len])),
                Err(InitError::InvalidKeyLength(len))
            );
        }
        assert_eq!(process(&mut engine, &CIPHERTEXT_256), PLAINTEXT);
    }

    /// Compares two engines on pseudorandom keys and blocks under every key
    /// size, and checks that `A` decrypts its own output.
    pub(crate) fn check_agreement<A: Engine, B: Engine>(new_a: fn() -> A, new_b: fn() -> B) {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        };
        for key_len in [16, 24, 32] {
            for _ in 0..32 {
                let key: [u8; 32] = core::array::from_fn(|_| next());
                let block: [u8; 16] = core::array::from_fn(|_| next());
                let key = &key[..key_len];
                let ciphertext = process(&mut keyed(new_a, CipherDirection::Encrypt, key), &block);
                let expected = process(&mut keyed(new_b, CipherDirection::Encrypt, key), &block);
                assert_eq!(ciphertext, expected, "{key_len}-byte key");
                let recovered = process(
                    &mut keyed(new_a, CipherDirection::Decrypt, key),
                    &ciphertext,
                );
                assert_eq!(recovered, block, "{key_len}-byte key");
            }
        }
    }

    /// [`check_agreement`] with the RustCrypto engine as the reference.
    #[cfg(feature = "rustcrypto")]
    pub(crate) fn check_against_rustcrypto<E: Engine>(new: fn() -> E) {
        check_agreement(new, crate::AesRustCryptoEngine::new);
    }
}
