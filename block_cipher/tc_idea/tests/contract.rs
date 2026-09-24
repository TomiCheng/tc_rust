//! State, buffer and initialization contracts for the IDEA engine.

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyRef,
};
use tc_idea_v2::{ALGO_NAME, BLOCK_BYTES, IdeaEngine, KEY_BYTES};

fn check_contract<E>(mut engine: E)
where
    E: core::fmt::Display
        + BlockCipher<Error = BlockError>
        + for<'a> BlockCipherInit<KeyRef<'a>, Error = InitError>
        + 'static,
{
    let mut untouched = [0x55; BLOCK_BYTES + 4];
    assert_eq!(engine.block_size(), BLOCK_BYTES);
    assert_eq!(engine.to_string(), ALGO_NAME);
    assert_eq!(
        engine.process_block(&[], &mut untouched),
        Err(BlockError::NotInitialised)
    );
    assert_eq!(untouched, [0x55; BLOCK_BYTES + 4]);

    for length in [0, KEY_BYTES - 1, KEY_BYTES + 1, 24, 32] {
        assert_eq!(
            engine.init(CipherDirection::Encrypt, &KeyRef::new(&[0; 32][..length])),
            Err(InitError::InvalidKeyLength(length))
        );
        assert_eq!(
            engine.process_block(&[0; BLOCK_BYTES], &mut untouched),
            Err(BlockError::NotInitialised)
        );
        assert_eq!(untouched, [0x55; BLOCK_BYTES + 4]);
    }

    let key = [0x42; KEY_BYTES];
    let plaintext = [0x11; BLOCK_BYTES + 4];
    let params = KeyRef::new(&key);
    engine.init(CipherDirection::Encrypt, &params).unwrap();
    let mut encrypted = [0x55; BLOCK_BYTES + 4];
    assert_eq!(
        engine.process_block(&plaintext, &mut encrypted),
        Ok(BLOCK_BYTES)
    );
    assert_eq!(&encrypted[BLOCK_BYTES..], &[0x55; 4]);

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
        for length in [0, KEY_BYTES - 1, KEY_BYTES + 1, 24, 32] {
            assert_eq!(
                engine.init(opposite, &KeyRef::new(&[0; 32][..length])),
                Err(InitError::InvalidKeyLength(length))
            );
            let mut actual = [0x55; BLOCK_BYTES + 4];
            assert_eq!(engine.process_block(input, &mut actual), Ok(BLOCK_BYTES));
            assert_eq!(&actual[..BLOCK_BYTES], &expected[..BLOCK_BYTES]);
            assert_eq!(&actual[BLOCK_BYTES..], &[0x55; 4]);
        }
        for length in [0, BLOCK_BYTES - 1] {
            assert_eq!(
                engine.process_block(&input[..length], &mut untouched),
                Err(BlockError::BufferTooShort)
            );
            assert_eq!(untouched, [0x55; BLOCK_BYTES + 4]);
            assert_eq!(
                engine.process_block(input, &mut untouched[..length]),
                Err(BlockError::BufferTooShort)
            );
            assert_eq!(untouched, [0x55; BLOCK_BYTES + 4]);
        }
        assert_eq!(engine.to_string(), ALGO_NAME);
    }

    let mut cipher: Box<dyn BlockCipher<Error = BlockError>> = Box::new(engine);
    assert_eq!(cipher.block_size(), BLOCK_BYTES);
    let mut recovered = [0x55; BLOCK_BYTES + 4];
    assert_eq!(
        cipher.process_block(&encrypted, &mut recovered),
        Ok(BLOCK_BYTES)
    );
    assert_eq!(&recovered[..BLOCK_BYTES], &plaintext[..BLOCK_BYTES]);
    assert_eq!(&recovered[BLOCK_BYTES..], &[0x55; 4]);
}

#[test]
fn the_idea_engine_preserves_state_on_errors_and_processes_one_block_through_either_dispatch() {
    check_contract(IdeaEngine::new());
}

#[test]
fn a_default_idea_engine_obeys_the_same_state_and_buffer_contract() {
    check_contract(IdeaEngine::default());
}
