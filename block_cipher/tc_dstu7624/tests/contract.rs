//! State, buffer and initialization contracts for the Kalyna engines.

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyRef,
};
use tc_dstu7624_v2::{ALGO_NAME, Dstu7624Engine128, Dstu7624Engine256, Dstu7624Engine512};

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
            engine.init(CipherDirection::Encrypt, &KeyRef::new(&vec![0; length])),
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
                engine.init(opposite, &KeyRef::new(&vec![0; length])),
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
fn every_kalyna_block_and_key_size_preserves_state_and_buffers_on_errors() {
    for size in [16, 32] {
        let invalid = &[0, 15, 17, 31, 33, 64, 65];
        check_contract(Dstu7624Engine128::new(), size, 16, ALGO_NAME, invalid);
        check_contract(Dstu7624Engine128::default(), size, 16, ALGO_NAME, invalid);
    }
    for size in [32, 64] {
        let invalid = &[0, 16, 31, 33, 63, 65];
        check_contract(Dstu7624Engine256::new(), size, 32, ALGO_NAME, invalid);
        check_contract(Dstu7624Engine256::default(), size, 32, ALGO_NAME, invalid);
    }
    let invalid = &[0, 16, 32, 63, 65];
    check_contract(Dstu7624Engine512::new(), 64, 64, ALGO_NAME, invalid);
    check_contract(Dstu7624Engine512::default(), 64, 64, ALGO_NAME, invalid);
}
