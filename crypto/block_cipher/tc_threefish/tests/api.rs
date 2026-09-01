use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::{KeyParams, TweakParams};
use tc_threefish::{
    Params, TWEAK_BYTES, Threefish256Engine, Threefish512Engine, Threefish1024Engine,
};

fn name(algorithm: &dyn AlgorithmName) -> String {
    let mut name = String::new();
    algorithm.write_algo_name(&mut name).unwrap();
    name
}

#[test]
fn variants_report_their_names_and_block_sizes() {
    let variants: [(&dyn AlgorithmName, usize); 3] = [
        (&Threefish256Engine::new(), 32),
        (&Threefish512Engine::new(), 64),
        (&Threefish1024Engine::new(), 128),
    ];
    for (engine, bits) in variants {
        assert_eq!(name(engine), format!("Threefish-{}", bits * 8));
    }

    assert_eq!(Threefish256Engine::new().block_size(), 32);
    assert_eq!(Threefish512Engine::new().block_size(), 64);
    assert_eq!(Threefish1024Engine::new().block_size(), 128);
}

#[test]
fn validates_state_key_tweak_and_buffers() {
    let mut engine = Threefish256Engine::new();
    assert_eq!(
        engine.process_block(&[0u8; 32], &mut [0u8; 32]),
        Err(BlockError::NotInitialised)
    );

    for length in [0, 31, 33, 64] {
        let key = vec![0u8; length];
        assert_eq!(
            engine.init(CipherDirection::Encrypt, &Params::new(&key)),
            Err(InitError::InvalidKeyLength(length))
        );
    }

    let key = [0u8; 32];
    for length in [0, TWEAK_BYTES - 1, TWEAK_BYTES + 1, 32] {
        let tweak = vec![0u8; length];
        assert_eq!(
            engine.init(CipherDirection::Encrypt, &Params::with_tweak(&key, &tweak),),
            Err(InitError::InvalidTweakLength(length))
        );
    }

    engine
        .init(CipherDirection::Encrypt, &Params::new(&key))
        .unwrap();
    assert_eq!(
        engine.process_block(&[0u8; 31], &mut [0u8; 32]),
        Err(BlockError::BufferTooShort)
    );
    assert_eq!(
        engine.process_block(&[0u8; 32], &mut [0u8; 31]),
        Err(BlockError::BufferTooShort)
    );
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

#[test]
fn absent_and_zero_tweaks_are_equivalent() {
    let key = [0u8; 32];
    let mut without_tweak = Threefish256Engine::new();
    let mut zero_tweak = Threefish256Engine::new();
    without_tweak
        .init(CipherDirection::Encrypt, &Params::new(&key))
        .unwrap();
    zero_tweak
        .init(
            CipherDirection::Encrypt,
            &Params::with_tweak(&key, &[0u8; TWEAK_BYTES]),
        )
        .unwrap();

    let mut first = [0u8; 32];
    let mut second = [0u8; 32];
    without_tweak.process_block(&[0u8; 32], &mut first).unwrap();
    zero_tweak.process_block(&[0u8; 32], &mut second).unwrap();
    assert_eq!(first, second);
}
