//! RFC 3394 section 4 known-answer tests.

use tc_aes::AesEngine;
use tc_cipher::{KeyWrap, KeyWrapInit, WrapDirection};
use tc_params::{KeyParams, KeyWithIvRef, OptionalIvParams};
use tc_rfc3394::{Rfc3394Error, Rfc3394WrapEngine};

struct DefaultIvParams<'a> {
    key: &'a [u8],
}

impl KeyParams for DefaultIvParams<'_> {
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl OptionalIvParams for DefaultIvParams<'_> {
    fn optional_iv(&self) -> Option<&[u8]> {
        None
    }
}

fn hex(input: &str) -> Vec<u8> {
    (0..input.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&input[index..index + 2], 16).unwrap())
        .collect()
}

fn check(kek: &str, key: &str, wrapped: &str) {
    let kek = hex(kek);
    let key = hex(key);
    let wrapped = hex(wrapped);
    let mut engine = Rfc3394WrapEngine::new(AesEngine::new());

    engine
        .init(WrapDirection::Wrap, &DefaultIvParams { key: &kek })
        .unwrap();
    let mut output = vec![0; engine.wrapped_len(key.len()).unwrap()];
    assert_eq!(engine.wrap_into(&key, &mut output).unwrap(), output.len());
    assert_eq!(output, wrapped);

    engine
        .init(WrapDirection::Unwrap, &DefaultIvParams { key: &kek })
        .unwrap();
    let mut recovered = vec![0; engine.max_unwrapped_len(wrapped.len()).unwrap()];
    let written = engine.unwrap_into(&wrapped, &mut recovered).unwrap();
    assert_eq!(&recovered[..written], key);
}

#[test]
fn official_vectors() {
    let vectors = [
        (
            "000102030405060708090A0B0C0D0E0F",
            "00112233445566778899AABBCCDDEEFF",
            "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
        ),
        (
            "000102030405060708090A0B0C0D0E0F1011121314151617",
            "00112233445566778899AABBCCDDEEFF",
            "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
        ),
        (
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "00112233445566778899AABBCCDDEEFF",
            "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7",
        ),
        (
            "000102030405060708090A0B0C0D0E0F1011121314151617",
            "00112233445566778899AABBCCDDEEFF0001020304050607",
            "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2",
        ),
        (
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "00112233445566778899AABBCCDDEEFF0001020304050607",
            "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
        ),
        (
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
            "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
        ),
    ];
    for (kek, key, wrapped) in vectors {
        check(kek, key, wrapped);
    }
}

#[test]
fn custom_iv_and_dynamic_dispatch() {
    let kek = hex("000102030405060708090A0B0C0D0E0F");
    let key = hex("00112233445566778899AABBCCDDEEFF");
    let iv = [1u8; 8];
    let mut engine = Rfc3394WrapEngine::new(AesEngine::new());
    engine
        .init(WrapDirection::Wrap, &KeyWithIvRef::new(&kek, &iv))
        .unwrap();
    let wrapper: &mut dyn KeyWrap<Error = Rfc3394Error<tc_cipher::BlockError>> = &mut engine;
    let mut wrapped = [0u8; 24];
    wrapper.wrap_into(&key, &mut wrapped).unwrap();

    engine
        .init(WrapDirection::Unwrap, &KeyWithIvRef::new(&kek, &iv))
        .unwrap();
    let mut recovered = [0u8; 16];
    assert_eq!(engine.unwrap_into(&wrapped, &mut recovered).unwrap(), 16);
    assert_eq!(recovered.as_slice(), key);
}

#[test]
fn tampering_clears_unauthenticated_output() {
    let kek = hex("000102030405060708090A0B0C0D0E0F");
    let mut wrapped = hex("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");
    wrapped[0] ^= 1;
    let mut engine = Rfc3394WrapEngine::new(AesEngine::new());
    engine
        .init(WrapDirection::Unwrap, &DefaultIvParams { key: &kek })
        .unwrap();
    let mut output = [0xa5; 16];
    assert!(matches!(
        engine.unwrap_into(&wrapped, &mut output),
        Err(Rfc3394Error::IntegrityCheckFailed)
    ));
    assert_eq!(output, [0; 16]);
}
