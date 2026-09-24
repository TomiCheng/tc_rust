//! State, buffer and initialization contracts for the Threefish engines.

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};
use tc_threefish_v2::{Params, TWEAK_BYTES, Threefish256Engine, ThreefishEngine, TweakParams};

fn check_contract<E>(
    mut engine: E,
    key_len: usize,
    block_bytes: usize,
    name: &str,
    invalid: &[usize],
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
            engine.init(CipherDirection::Encrypt, &Params::new(&vec![0; length])),
            Err(InitError::InvalidKeyLength(length))
        );
        assert_eq!(
            engine.process_block(&vec![0; block_bytes], &mut untouched),
            Err(BlockError::NotInitialised)
        );
        assert_eq!(untouched, vec![0x55; block_bytes + 4]);
    }

    let key = vec![0x42; key_len];
    for length in [0, 15, 17, 32] {
        assert_eq!(
            engine.init(
                CipherDirection::Encrypt,
                &Params::with_tweak(&key, &vec![0; length])
            ),
            Err(InitError::InvalidTweakLength(length))
        );
        assert_eq!(
            engine.process_block(&[], &mut untouched),
            Err(BlockError::NotInitialised)
        );
        assert_eq!(untouched, vec![0x55; block_bytes + 4]);
    }
    let plaintext = vec![0x11; block_bytes + 4];
    let tweak = [0x37; TWEAK_BYTES];
    let params = Params::with_tweak(&key, &tweak);
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
                engine.init(opposite, &Params::new(&vec![0; length])),
                Err(InitError::InvalidKeyLength(length))
            );
            let mut actual = vec![0x55; block_bytes + 4];
            assert_eq!(engine.process_block(input, &mut actual), Ok(block_bytes));
            assert_eq!(&actual[..block_bytes], &expected[..block_bytes]);
            assert_eq!(&actual[block_bytes..], &[0x55; 4]);
        }
        for length in [0, 15, 17, 32] {
            assert_eq!(
                engine.init(opposite, &Params::with_tweak(&key, &vec![0; length])),
                Err(InitError::InvalidTweakLength(length))
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

fn check_variant<const WORDS: usize>() {
    let size = WORDS * 8;
    let name = format!("Threefish-{}", size * 8);
    let invalid = &[0, size - 1, size + 1, size * 2];
    check_contract(ThreefishEngine::<WORDS>::new(), size, size, &name, invalid);
    check_contract(
        ThreefishEngine::<WORDS>::default(),
        size,
        size,
        &name,
        invalid,
    );
    let mut engine = ThreefishEngine::<WORDS>::new();
    let key = vec![0x42; size];
    for direction in [CipherDirection::Encrypt, CipherDirection::Decrypt] {
        let mut absent = vec![0; size];
        let mut zero = vec![0; size];
        engine.init(direction, &Params::new(&key)).unwrap();
        engine
            .process_block(&vec![0x11; size], &mut absent)
            .unwrap();
        engine
            .init(direction, &Params::with_tweak(&key, &[0; TWEAK_BYTES]))
            .unwrap();
        engine.process_block(&vec![0x11; size], &mut zero).unwrap();
        assert_eq!(absent, zero);
    }
}

#[test]
fn all_threefish_variants_preserve_state_on_invalid_keys_or_tweaks_and_treat_absent_tweaks_as_zero()
{
    check_variant::<4>();
    check_variant::<8>();
    check_variant::<16>();
}

struct ThirdPartyParams<'a> {
    key: &'a [u8],
    tweak: Option<&'a [u8]>,
}

impl KeyParams for ThirdPartyParams<'_> {
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl TweakParams for ThirdPartyParams<'_> {
    fn tweak(&self) -> Option<&[u8]> {
        self.tweak
    }
}

#[test]
fn accepts_third_party_params_and_supports_dynamic_dispatch() {
    let params = ThirdPartyParams {
        key: &[0u8; 32],
        tweak: None,
    };
    let mut engine = Threefish256Engine::new();
    engine.init(CipherDirection::Encrypt, &params).unwrap();

    let mut cipher: Box<dyn BlockCipher<Error = BlockError>> = Box::new(engine);
    let mut output = [0u8; 32];
    assert_eq!(cipher.process_block(&[0u8; 32], &mut output), Ok(32));
}
