//! AES through the RustCrypto `aes` crate.

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256, Block};
use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};

use crate::BLOCK_BYTES;

enum Cipher {
    Aes128(Aes128),
    Aes192(Aes192),
    Aes256(Aes256),
}

/// AES backed by the RustCrypto `aes` crate, which picks AES-NI, VAES or
/// ARMv8 at runtime and otherwise a bitsliced software implementation with
/// no table lookups. Constant time on every backend; its round keys are wiped
/// on drop.
pub struct AesRustCryptoEngine {
    cipher: Option<Cipher>,
    direction: CipherDirection,
}

impl AesRustCryptoEngine {
    /// An engine without a key; `init` must come before `process_block`.
    /// Constant time.
    pub const fn new() -> Self {
        Self {
            cipher: None,
            direction: CipherDirection::Encrypt,
        }
    }
}

impl Default for AesRustCryptoEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: KeyParams + ?Sized> BlockCipherInit<P> for AesRustCryptoEngine {
    type Error = InitError;

    /// Expands a 16-, 24- or 32-byte key. Branches on the key length, which is
    /// public, and is otherwise constant time. A rejected key leaves the
    /// previous state in place.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        let invalid = |_| InitError::InvalidKeyLength(key.len());
        let cipher = match key.len() {
            16 => Cipher::Aes128(Aes128::new_from_slice(key).map_err(invalid)?),
            24 => Cipher::Aes192(Aes192::new_from_slice(key).map_err(invalid)?),
            32 => Cipher::Aes256(Aes256::new_from_slice(key).map_err(invalid)?),
            len => return Err(InitError::InvalidKeyLength(len)),
        };
        self.cipher = Some(cipher);
        self.direction = direction;
        Ok(())
    }
}

impl BlockCipher for AesRustCryptoEngine {
    type Error = BlockError;

    /// Always 16. Constant time.
    fn block_size(&self) -> usize {
        BLOCK_BYTES
    }

    /// Transforms the first 16 bytes of `input` into the first 16 of
    /// `output`. Constant time in the key and the data; branches only on
    /// the key size and direction.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        let cipher = self.cipher.as_ref().ok_or(BlockError::NotInitialised)?;
        let (Some(input), Some(output)) = (
            input.get(..BLOCK_BYTES).and_then(Block::slice_as_array),
            output
                .get_mut(..BLOCK_BYTES)
                .and_then(Block::slice_as_mut_array),
        ) else {
            return Err(BlockError::BufferTooShort);
        };
        match (cipher, self.direction) {
            (Cipher::Aes128(c), CipherDirection::Encrypt) => c.encrypt_block_b2b(input, output),
            (Cipher::Aes128(c), CipherDirection::Decrypt) => c.decrypt_block_b2b(input, output),
            (Cipher::Aes192(c), CipherDirection::Encrypt) => c.encrypt_block_b2b(input, output),
            (Cipher::Aes192(c), CipherDirection::Decrypt) => c.decrypt_block_b2b(input, output),
            (Cipher::Aes256(c), CipherDirection::Encrypt) => c.encrypt_block_b2b(input, output),
            (Cipher::Aes256(c), CipherDirection::Decrypt) => c.decrypt_block_b2b(input, output),
        }
        Ok(BLOCK_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use tc_block_cipher::{
        BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyRef,
    };

    use super::AesRustCryptoEngine;

    // FIPS 197 Appendix C: one plaintext, keys counting up from 00.
    const PLAINTEXT: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    const CIPHERTEXT_128: [u8; 16] = [
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5,
        0x5a,
    ];
    const CIPHERTEXT_192: [u8; 16] = [
        0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71,
        0x91,
    ];
    const CIPHERTEXT_256: [u8; 16] = [
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60,
        0x89,
    ];

    fn counting_key<const N: usize>() -> [u8; N] {
        core::array::from_fn(|i| i as u8)
    }

    fn keyed(direction: CipherDirection, key: &[u8]) -> AesRustCryptoEngine {
        let mut engine = AesRustCryptoEngine::new();
        engine.init(direction, &KeyRef::new(key)).unwrap();
        engine
    }

    fn process(engine: &mut AesRustCryptoEngine, input: &[u8; 16]) -> [u8; 16] {
        let mut output = [0; 16];
        assert_eq!(engine.process_block(input, &mut output), Ok(16));
        output
    }

    #[test]
    fn fips_197_vectors_encrypt_and_decrypt_under_every_key_size() {
        let (key_128, key_192, key_256) = (
            counting_key::<16>(),
            counting_key::<24>(),
            counting_key::<32>(),
        );
        let cases: [(&[u8], [u8; 16]); 3] = [
            (&key_128, CIPHERTEXT_128),
            (&key_192, CIPHERTEXT_192),
            (&key_256, CIPHERTEXT_256),
        ];
        for (key, ciphertext) in cases {
            let mut encryptor = keyed(CipherDirection::Encrypt, key);
            assert_eq!(
                process(&mut encryptor, &PLAINTEXT),
                ciphertext,
                "{}-byte key",
                key.len()
            );
            let mut decryptor = keyed(CipherDirection::Decrypt, key);
            assert_eq!(
                process(&mut decryptor, &ciphertext),
                PLAINTEXT,
                "{}-byte key",
                key.len()
            );
        }
    }

    #[test]
    fn processing_before_init_is_rejected() {
        let mut engine = AesRustCryptoEngine::default();
        assert_eq!(engine.block_size(), 16);
        assert_eq!(
            engine.process_block(&[0; 16], &mut [0; 16]),
            Err(BlockError::NotInitialised)
        );
    }

    #[test]
    fn short_buffers_are_rejected_and_longer_ones_get_exactly_one_block() {
        let mut engine = keyed(CipherDirection::Encrypt, &counting_key::<16>());
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

    #[test]
    fn a_rejected_key_length_keeps_the_previous_key() {
        let mut engine = keyed(CipherDirection::Decrypt, &counting_key::<32>());
        let too_long = [0; 33];
        for len in [0, 15, 17, 23, 25, 31, 33] {
            assert_eq!(
                engine.init(CipherDirection::Encrypt, &KeyRef::new(&too_long[..len])),
                Err(InitError::InvalidKeyLength(len))
            );
        }
        assert_eq!(process(&mut engine, &CIPHERTEXT_256), PLAINTEXT);
    }
}
