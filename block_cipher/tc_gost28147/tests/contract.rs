//! State, buffer and initialization contracts for the GOST 28147 engine.

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};
use tc_gost28147_v2::{
    ALGO_NAME, BLOCK_BYTES, Gost28147Engine, KEY_BYTES, KeyWithSBox, SBoxParams, s_box,
};

fn check_contract<E>(mut engine: E, table: &[u8])
where
    E: core::fmt::Display
        + BlockCipher<Error = BlockError>
        + for<'a> BlockCipherInit<KeyWithSBox<'a>, Error = InitError>
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

    for length in [0, KEY_BYTES - 1, KEY_BYTES + 1, 16, 24] {
        assert_eq!(
            engine.init(
                CipherDirection::Encrypt,
                &KeyWithSBox::new(&vec![0; length])
            ),
            Err(InitError::InvalidKeyLength(length))
        );
        assert_eq!(
            engine.process_block(&[0; BLOCK_BYTES], &mut untouched),
            Err(BlockError::NotInitialised)
        );
        assert_eq!(untouched, [0x55; BLOCK_BYTES + 4]);
    }

    let key = [0x42; KEY_BYTES];
    for length in [0, 64, 127, 129, 256] {
        assert_eq!(
            engine.init(
                CipherDirection::Encrypt,
                &KeyWithSBox::with_s_box(&key, &vec![0; length])
            ),
            Err(InitError::InvalidSBoxLength(length))
        );
        assert_eq!(
            engine.process_block(&[], &mut untouched),
            Err(BlockError::NotInitialised)
        );
        assert_eq!(untouched, [0x55; BLOCK_BYTES + 4]);
    }
    let plaintext = [0x11; BLOCK_BYTES + 4];
    let params = KeyWithSBox::with_s_box(&key, table);
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
        for length in [0, KEY_BYTES - 1, KEY_BYTES + 1, 16, 24] {
            assert_eq!(
                engine.init(opposite, &KeyWithSBox::new(&vec![0; length])),
                Err(InitError::InvalidKeyLength(length))
            );
            let mut actual = [0x55; BLOCK_BYTES + 4];
            assert_eq!(engine.process_block(input, &mut actual), Ok(BLOCK_BYTES));
            assert_eq!(&actual[..BLOCK_BYTES], &expected[..BLOCK_BYTES]);
            assert_eq!(&actual[BLOCK_BYTES..], &[0x55; 4]);
        }
        for length in [0, 64, 127, 129, 256] {
            assert_eq!(
                engine.init(opposite, &KeyWithSBox::with_s_box(&key, &vec![0; length])),
                Err(InitError::InvalidSBoxLength(length))
            );
            let mut actual = [0x55; BLOCK_BYTES + 4];
            engine.process_block(input, &mut actual).unwrap();
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
fn gost_preserves_key_table_direction_and_buffers_on_invalid_parameters_for_every_standard_table() {
    for table in [
        s_box::DEFAULT,
        s_box::D_TEST,
        s_box::E_TEST,
        s_box::E_A,
        s_box::E_B,
        s_box::E_C,
        s_box::E_D,
        s_box::D_A,
        [0; s_box::BYTES],
        [0xff; s_box::BYTES],
    ] {
        check_contract(Gost28147Engine::new(), &table);
        check_contract(Gost28147Engine::default(), &table);
    }
}

#[test]
fn custom_parameter_types_can_supply_a_key_and_s_box() {
    struct Custom<'a> {
        key: &'a [u8],
        table: &'a [u8],
    }
    impl KeyParams for Custom<'_> {
        fn key(&self) -> &[u8] {
            self.key
        }
    }
    impl SBoxParams for Custom<'_> {
        fn s_box(&self) -> &[u8] {
            self.table
        }
    }
    let key = [0x42; KEY_BYTES];
    let custom = Custom {
        key: &key,
        table: &s_box::E_A,
    };
    let mut engine = Gost28147Engine::new();
    let mut expected = [0; BLOCK_BYTES];
    let mut actual = [0; BLOCK_BYTES];
    engine
        .init(
            CipherDirection::Encrypt,
            &KeyWithSBox::with_s_box(&key, &s_box::E_A),
        )
        .unwrap();
    engine
        .process_block(&[0x11; BLOCK_BYTES], &mut expected)
        .unwrap();
    engine.init(CipherDirection::Encrypt, &custom).unwrap();
    engine
        .process_block(&[0x11; BLOCK_BYTES], &mut actual)
        .unwrap();
    assert_eq!(actual, expected);
}
