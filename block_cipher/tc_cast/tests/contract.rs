//! State, buffer and initialization contracts for the CAST5 and CAST6 engines.

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyRef,
};
use tc_cast_v2::{Cast5Engine, Cast6Engine, cast5, cast6};

fn check_contract<E>(
    mut engine: E,
    key_len: usize,
    block_bytes: usize,
    name: &str,
    invalid: &[usize],
) where
    E: core::fmt::Display
        + BlockCipher<Error = BlockError>
        + for<'a> BlockCipherInit<KeyRef<'a>, Error = InitError>
        + 'static,
{
    let mut untouched = vec![0x55; block_bytes + 4];
    assert_eq!(engine.block_size(), block_bytes);
    assert_eq!(engine.to_string(), name);
    assert_eq!(
        engine.process_block(&[], &mut untouched),
        Err(BlockError::NotInitialised)
    );
    assert_eq!(untouched, vec![0x55; block_bytes + 4]);

    for &length in invalid {
        assert_eq!(
            engine.init(CipherDirection::Encrypt, &KeyRef::new(&[0; 64][..length])),
            Err(InitError::InvalidKeyLength(length))
        );
        assert_eq!(
            engine.process_block(&vec![0; block_bytes], &mut untouched),
            Err(BlockError::NotInitialised)
        );
        assert_eq!(untouched, vec![0x55; block_bytes + 4]);
    }

    let key = vec![0x42; key_len];
    let plaintext = vec![0x11; block_bytes + 4];
    let params = KeyRef::new(&key);
    engine.init(CipherDirection::Encrypt, &params).unwrap();
    let mut encrypted = vec![0x55; block_bytes + 4];
    assert_eq!(
        engine.process_block(&plaintext, &mut encrypted),
        Ok(block_bytes)
    );
    assert_eq!(&encrypted[block_bytes..], &[0x55; 4]);

    for (direction, opposite, input, expected) in [
        (
            CipherDirection::Encrypt,
            CipherDirection::Decrypt,
            &plaintext,
            &encrypted,
        ),
        (
            CipherDirection::Decrypt,
            CipherDirection::Encrypt,
            &encrypted,
            &plaintext,
        ),
    ] {
        engine.init(direction, &params).unwrap();
        for &length in invalid {
            assert_eq!(
                engine.init(opposite, &KeyRef::new(&[0; 64][..length])),
                Err(InitError::InvalidKeyLength(length))
            );
            let mut actual = vec![0x55; block_bytes + 4];
            assert_eq!(engine.process_block(input, &mut actual), Ok(block_bytes));
            assert_eq!(&actual[..block_bytes], &expected[..block_bytes]);
            assert_eq!(&actual[block_bytes..], &[0x55; 4]);
        }
        for length in [0, block_bytes - 1] {
            assert_eq!(
                engine.process_block(&input[..length], &mut untouched),
                Err(BlockError::BufferTooShort)
            );
            assert_eq!(untouched, vec![0x55; block_bytes + 4]);
            assert_eq!(
                engine.process_block(input, &mut untouched[..length]),
                Err(BlockError::BufferTooShort)
            );
            assert_eq!(untouched, vec![0x55; block_bytes + 4]);
        }
        assert_eq!(engine.to_string(), name);
    }

    let mut cipher: Box<dyn BlockCipher<Error = BlockError>> = Box::new(engine);
    assert_eq!(cipher.block_size(), block_bytes);
    let mut recovered = vec![0x55; block_bytes + 4];
    assert_eq!(
        cipher.process_block(&encrypted, &mut recovered),
        Ok(block_bytes)
    );
    assert_eq!(&recovered[..block_bytes], &plaintext[..block_bytes]);
    assert_eq!(&recovered[block_bytes..], &[0x55; 4]);
}

#[test]
fn both_cast_engines_preserve_state_on_errors_for_every_accepted_key_size() {
    for size in cast5::MIN_KEY_BYTES..=cast5::MAX_KEY_BYTES {
        check_contract(
            Cast5Engine::new(),
            size,
            cast5::BLOCK_BYTES,
            cast5::ALGO_NAME,
            &[0, 4, 17, 32],
        );
        check_contract(
            Cast5Engine::default(),
            size,
            cast5::BLOCK_BYTES,
            cast5::ALGO_NAME,
            &[0, 4, 17, 32],
        );
    }
    for size in cast6::KEY_BYTES {
        check_contract(
            Cast6Engine::new(),
            size,
            cast6::BLOCK_BYTES,
            cast6::ALGO_NAME,
            &[0, 15, 17, 19, 21, 27, 29, 31, 33],
        );
        check_contract(
            Cast6Engine::default(),
            size,
            cast6::BLOCK_BYTES,
            cast6::ALGO_NAME,
            &[0, 15, 17, 19, 21, 27, 29, 31, 33],
        );
    }
}
