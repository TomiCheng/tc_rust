//! RFC 5649 and independent ARIA known-answer tests.

use tc_aes::AesEngine;
use tc_aria::AriaEngine;
use tc_cipher::{KeyWrap, KeyWrapInit, WrapDirection};
use tc_params::{KeyParams, KeyWithIvRef, OptionalIvParams};
use tc_rfc5649::{Rfc5649Error, Rfc5649WrapEngine};

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

fn check<C>(mut engine: Rfc5649WrapEngine<C>, kek: &str, key: &str, wrapped: &str)
where
    C: tc_cipher::BlockCipher<Error = tc_cipher::BlockError>
        + for<'a> tc_cipher::BlockCipherInit<DefaultIvParams<'a>, Error = tc_cipher::InitError>,
{
    let kek = hex(kek);
    let key = hex(key);
    let wrapped = hex(wrapped);
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
fn official_aes_vectors() {
    let kek = "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8";
    check(
        Rfc5649WrapEngine::new(AesEngine::new()),
        kek,
        "c37b7e6492584340bed12207808941155068f738",
        "138BDEAA9B8FA7FC61F97742E72248EE5AE6AE5360D1AE6A5F54F373FA543B6A",
    );
    check(
        Rfc5649WrapEngine::new(AesEngine::new()),
        kek,
        "466f7250617369",
        "AFBEB0F07DFBF5419200F2CCB50BB24F",
    );
}

#[test]
fn independent_aria_vectors() {
    let kek = "000102030405060708090A0B0C0D0E0F";
    let vectors = [
        ("466f7250617369", "FF5DF3FABA86BD7802800F420B6BB16A"),
        (
            "00112233445566778899AABBCCDDEEFF",
            "AC0E22699A036CED63ADEB75F4946F82DC98AD8AF43B24D5",
        ),
        (
            "c37b7e6492584340bed12207808941155068f738",
            "9EC1DA50BA6665264E0C75C4C4FD2E652DEB5F4C0F3FCFD478624C1A9AF35FFA",
        ),
        (
            "00112233445566778899AABBCCDDEEFF0001020304050607",
            "A08391E5159F4DE68EBD1F9E7DB722E1A9D9AAF206F7DACB62CA0FEAD47C1B96",
        ),
        (
            "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
            "1F59D0D10409835594531BF7B721CBF260816766D71BF2647D8BA6AB3125334E34FA018ABB39C280",
        ),
    ];
    for (key, wrapped) in vectors {
        check(Rfc5649WrapEngine::new(AriaEngine::new()), kek, key, wrapped);
    }
}

#[test]
fn tampering_clears_unauthenticated_output() {
    let kek = hex("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
    let mut wrapped = hex("AFBEB0F07DFBF5419200F2CCB50BB24F");
    wrapped[0] ^= 1;
    let mut engine = Rfc5649WrapEngine::new(AesEngine::new());
    engine
        .init(WrapDirection::Unwrap, &DefaultIvParams { key: &kek })
        .unwrap();
    let mut output = [0xa5; 8];
    assert!(matches!(
        engine.unwrap_into(&wrapped, &mut output),
        Err(Rfc5649Error::IntegrityCheckFailed)
    ));
    assert_eq!(output, [0; 8]);
}

#[test]
fn custom_pre_iv_round_trips() {
    let key = hex("000102030405060708090A0B0C0D0E0F");
    let input = hex("466f7250617369");
    let pre_iv = [1u8, 2, 3, 4];
    let params = KeyWithIvRef::new(&key, &pre_iv);
    let mut engine = Rfc5649WrapEngine::new(AesEngine::new());
    engine.init(WrapDirection::Wrap, &params).unwrap();
    let mut wrapped = [0u8; 16];
    engine.wrap_into(&input, &mut wrapped).unwrap();

    engine.init(WrapDirection::Unwrap, &params).unwrap();
    let mut recovered = [0u8; 8];
    let written = engine.unwrap_into(&wrapped, &mut recovered).unwrap();
    assert_eq!(&recovered[..written], input);
}
