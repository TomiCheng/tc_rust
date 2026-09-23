use tc_aes::{ALGO_NAME, AesEngine, AesLightEngine, AesTableEngine};
use tc_block_cipher::{BlockCipherInit, CipherDirection, InitError, KeyRef};

fn check_name<E>(mut engine: E)
where
    E: core::fmt::Display + for<'a> BlockCipherInit<KeyRef<'a>, Error = InitError>,
{
    assert_eq!(engine.to_string(), ALGO_NAME);
    for key_len in [16, 24, 32] {
        for direction in [CipherDirection::Encrypt, CipherDirection::Decrypt] {
            engine
                .init(direction, &KeyRef::new(&[0x11; 32][..key_len]))
                .unwrap();
            assert_eq!(engine.to_string(), ALGO_NAME);
        }
    }
}

#[test]
fn dispatcher_and_portable_engines_display_the_algorithm_name_before_and_after_init() {
    check_name(AesEngine::new());
    check_name(AesTableEngine::new());
    check_name(AesLightEngine::new());
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[test]
fn the_x86_engine_displays_the_same_algorithm_name_when_available() {
    if let Some(engine) = tc_aes::AesX86Engine::new() {
        check_name(engine);
    }
}

#[cfg(feature = "rustcrypto")]
#[test]
fn the_rustcrypto_engine_displays_the_same_algorithm_name() {
    check_name(tc_aes::AesRustCryptoEngine::new());
}
