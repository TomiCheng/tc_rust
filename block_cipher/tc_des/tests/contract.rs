//! State, buffer and initialization contracts for the DES and Triple DES engines.

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyRef,
};
use tc_des_v2::{
    BLOCK_BYTES, DES_ALGO_NAME, DES_EDE_ALGO_NAME, DesEdeEngine, DesEngine, EDE2_KEY_BYTES,
    EDE3_KEY_BYTES, KEY_BYTES,
};

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
fn des_and_triple_des_preserve_state_on_errors_at_every_accepted_key_size() {
    check_contract(
        DesEngine::new(),
        KEY_BYTES,
        BLOCK_BYTES,
        DES_ALGO_NAME,
        &[0, 7, 9, 16, 24],
    );
    check_contract(
        DesEngine::default(),
        KEY_BYTES,
        BLOCK_BYTES,
        DES_ALGO_NAME,
        &[0, 7, 9, 16, 24],
    );
    for size in [EDE2_KEY_BYTES, EDE3_KEY_BYTES] {
        check_contract(
            DesEdeEngine::new(),
            size,
            BLOCK_BYTES,
            DES_EDE_ALGO_NAME,
            &[0, 8, 15, 17, 23, 25],
        );
        check_contract(
            DesEdeEngine::default(),
            size,
            BLOCK_BYTES,
            DES_EDE_ALGO_NAME,
            &[0, 8, 15, 17, 23, 25],
        );
    }
}

fn parity_is_ignored<E>(mut engine: E, key_len: usize)
where
    E: BlockCipher<Error = BlockError> + for<'a> BlockCipherInit<KeyRef<'a>, Error = InitError>,
{
    let key: Vec<u8> = (0..key_len).map(|i| (i as u8).wrapping_mul(0x37)).collect();
    let toggled: Vec<u8> = key.iter().map(|byte| byte ^ 1).collect();
    for direction in [CipherDirection::Encrypt, CipherDirection::Decrypt] {
        let mut first = [0; BLOCK_BYTES];
        let mut second = [0; BLOCK_BYTES];
        engine.init(direction, &KeyRef::new(&key)).unwrap();
        engine
            .process_block(&[0x42; BLOCK_BYTES], &mut first)
            .unwrap();
        engine.init(direction, &KeyRef::new(&toggled)).unwrap();
        engine
            .process_block(&[0x42; BLOCK_BYTES], &mut second)
            .unwrap();
        assert_eq!(first, second);
    }
}

#[test]
fn changing_only_parity_bits_does_not_change_des_or_triple_des_outputs() {
    parity_is_ignored(DesEngine::new(), KEY_BYTES);
    parity_is_ignored(DesEdeEngine::new(), EDE2_KEY_BYTES);
    parity_is_ignored(DesEdeEngine::new(), EDE3_KEY_BYTES);
}
