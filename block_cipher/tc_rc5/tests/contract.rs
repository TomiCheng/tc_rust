//! State, buffer and initialization contracts for the RC5 engines.

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};
use tc_rc5_v2::{
    MAX_KEY_BYTES, MAX_ROUNDS, Params, RC5_32_ALGO_NAME, RC5_32_BLOCK_BYTES, RC5_64_ALGO_NAME,
    RC5_64_BLOCK_BYTES, Rc5Params, Rc532Engine, Rc564Engine,
};

fn check_contract<E>(
    mut engine: E,
    key_len: usize,
    block_bytes: usize,
    name: &str,
    invalid: &[usize],
    rounds: usize,
) where
    E: core::fmt::Display
        + BlockCipher<Error = BlockError>
        + for<'a> BlockCipherInit<Params<'a>, Error = InitError>
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
            engine.init(
                CipherDirection::Encrypt,
                &Params::new(&vec![0; length], rounds)
            ),
            Err(InitError::InvalidKeyLength(length))
        );
        assert_eq!(
            engine.process_block(&vec![0; block_bytes], &mut untouched),
            Err(BlockError::NotInitialised)
        );
        assert_eq!(untouched, vec![0x55; block_bytes + 4]);
    }

    let key = vec![0x42; key_len];
    for rounds in [MAX_ROUNDS + 1, usize::MAX] {
        assert_eq!(
            engine.init(CipherDirection::Encrypt, &Params::new(&key, rounds)),
            Err(InitError::InvalidRounds(rounds))
        );
        assert_eq!(
            engine.process_block(&[], &mut untouched),
            Err(BlockError::NotInitialised)
        );
        assert_eq!(untouched, vec![0x55; block_bytes + 4]);
    }
    let plaintext = vec![0x11; block_bytes + 4];
    let params = Params::new(&key, rounds);
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
                engine.init(opposite, &Params::new(&vec![0; length], rounds)),
                Err(InitError::InvalidKeyLength(length))
            );
            let mut actual = vec![0x55; block_bytes + 4];
            assert_eq!(engine.process_block(input, &mut actual), Ok(block_bytes));
            assert_eq!(&actual[..block_bytes], &expected[..block_bytes]);
            assert_eq!(&actual[block_bytes..], &[0x55; 4]);
        }
        for rounds in [MAX_ROUNDS + 1, usize::MAX] {
            assert_eq!(
                engine.init(opposite, &Params::new(&key, rounds)),
                Err(InitError::InvalidRounds(rounds))
            );
            let mut actual = vec![0x55; block_bytes + 4];
            engine.process_block(input, &mut actual).unwrap();
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
fn both_rc5_word_sizes_preserve_state_at_every_key_length_and_round_boundaries() {
    for size in 1..=MAX_KEY_BYTES {
        for rounds in [0, 1, 12, MAX_ROUNDS] {
            let invalid = &[0, MAX_KEY_BYTES + 1];
            check_contract(
                Rc532Engine::new(),
                size,
                RC5_32_BLOCK_BYTES,
                RC5_32_ALGO_NAME,
                invalid,
                rounds,
            );
            check_contract(
                Rc532Engine::default(),
                size,
                RC5_32_BLOCK_BYTES,
                RC5_32_ALGO_NAME,
                invalid,
                rounds,
            );
            check_contract(
                Rc564Engine::new(),
                size,
                RC5_64_BLOCK_BYTES,
                RC5_64_ALGO_NAME,
                invalid,
                rounds,
            );
            check_contract(
                Rc564Engine::default(),
                size,
                RC5_64_BLOCK_BYTES,
                RC5_64_ALGO_NAME,
                invalid,
                rounds,
            );
        }
    }
}

#[test]
fn both_rc5_engines_accept_every_round_count_including_zero() {
    for rounds in 0..=MAX_ROUNDS {
        check_contract(
            Rc532Engine::new(),
            7,
            RC5_32_BLOCK_BYTES,
            RC5_32_ALGO_NAME,
            &[0, MAX_KEY_BYTES + 1],
            rounds,
        );
        check_contract(
            Rc564Engine::new(),
            7,
            RC5_64_BLOCK_BYTES,
            RC5_64_ALGO_NAME,
            &[0, MAX_KEY_BYTES + 1],
            rounds,
        );
    }
}

#[test]
fn accepts_custom_parameter_implementations() {
    struct Custom<'a> {
        key: &'a [u8],
        rounds: usize,
    }

    impl KeyParams for Custom<'_> {
        fn key(&self) -> &[u8] {
            self.key
        }
    }

    impl Rc5Params for Custom<'_> {
        fn rounds(&self) -> usize {
            self.rounds
        }
    }

    let params = Custom {
        key: &[0u8; 16],
        rounds: 16,
    };
    assert!(
        Rc532Engine::new()
            .init(CipherDirection::Encrypt, &params)
            .is_ok()
    );
    assert!(
        Rc564Engine::new()
            .init(CipherDirection::Encrypt, &params)
            .is_ok()
    );
}
