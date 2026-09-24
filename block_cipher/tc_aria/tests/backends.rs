//! Shared contracts and differential checks for the available ARIA backends.

use tc_aria::{ALGO_NAME, AriaEngine, AriaTableEngine};
use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyRef,
};

fn check_contract<E>(mut engine: E)
where
    E: core::fmt::Display
        + BlockCipher<Error = BlockError>
        + for<'a> BlockCipherInit<KeyRef<'a>, Error = InitError>,
{
    let mut untouched = [0x55; 20];
    assert_eq!(
        engine.process_block(&[], &mut untouched),
        Err(BlockError::NotInitialised)
    );
    assert_eq!(untouched, [0x55; 20]);
    assert_eq!(engine.to_string(), ALGO_NAME);
    for size in [32, 16, 24] {
        let key = [0x42; 32];
        let params = KeyRef::new(&key[..size]);
        let plaintext = [0x11; 20];
        engine.init(CipherDirection::Encrypt, &params).unwrap();
        let mut encrypted = [0x55; 20];
        assert_eq!(engine.process_block(&plaintext, &mut encrypted), Ok(16));
        assert_eq!(&encrypted[16..], &[0x55; 4]);
        engine.init(CipherDirection::Decrypt, &params).unwrap();
        for len in [0, 15, 17, 23, 25, 31, 33] {
            assert_eq!(
                engine.init(CipherDirection::Encrypt, &KeyRef::new(&[0; 33][..len])),
                Err(InitError::InvalidKeyLength(len)),
            );
        }
        let mut recovered = [0x55; 20];
        assert_eq!(engine.process_block(&encrypted, &mut recovered), Ok(16));
        assert_eq!(&recovered[..16], &plaintext[..16]);
        assert_eq!(&recovered[16..], &[0x55; 4]);
        assert_eq!(
            engine.process_block(&encrypted[..15], &mut untouched),
            Err(BlockError::BufferTooShort)
        );
        assert_eq!(
            engine.process_block(&encrypted, &mut untouched[..15]),
            Err(BlockError::BufferTooShort)
        );
        assert_eq!(untouched, [0x55; 20]);
        assert_eq!(engine.to_string(), ALGO_NAME);
    }
}

#[test]
fn table_and_dispatch_engines_preserve_state_on_errors_and_process_only_one_block() {
    check_contract(AriaTableEngine::new());
    check_contract(AriaEngine::new());
}

#[cfg(feature = "rustcrypto")]
#[test]
fn the_rustcrypto_engine_obeys_the_same_state_buffer_and_display_contracts() {
    check_contract(tc_aria::AriaRustCryptoEngine::new());
}

#[cfg(feature = "rustcrypto")]
#[test]
fn both_backends_agree_on_pseudorandom_keys_and_blocks_in_both_directions() {
    use tc_aria::AriaRustCryptoEngine;

    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed as u8
    };
    for size in [16, 24, 32] {
        for _ in 0..64 {
            let key: [u8; 32] = core::array::from_fn(|_| next());
            let input: [u8; 16] = core::array::from_fn(|_| next());
            for direction in [CipherDirection::Encrypt, CipherDirection::Decrypt] {
                let params = KeyRef::new(&key[..size]);
                let mut table = AriaTableEngine::new();
                let mut rustcrypto = AriaRustCryptoEngine::new();
                table.init(direction, &params).unwrap();
                rustcrypto.init(direction, &params).unwrap();
                let mut expected = [0; 16];
                let mut actual = [0; 16];
                table.process_block(&input, &mut expected).unwrap();
                rustcrypto.process_block(&input, &mut actual).unwrap();
                assert_eq!(actual, expected, "{size}-byte key, {direction:?}");
            }
        }
    }
}
