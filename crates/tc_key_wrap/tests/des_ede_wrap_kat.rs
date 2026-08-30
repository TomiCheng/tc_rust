//! CMS Triple-DES key-wrap tests using Bouncy Castle's fixed vector.

use core::convert::Infallible;

use rand_core::{TryCryptoRng, TryRng};
use tc_block_cipher::DesEdeParams;
use tc_cipher_core::{KeyWrap, KeyWrapInit, WrapDirection};
use tc_key_wrap::{DesEdeWrapEngine, DesEdeWrapError, DesEdeWrapParams, WrapError};

fn hex(input: &str) -> Vec<u8> {
    (0..input.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&input[index..index + 2], 16).unwrap())
        .collect()
}

struct FixedCryptoRng {
    bytes: Vec<u8>,
    offset: usize,
}

impl FixedCryptoRng {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, output: &mut [u8]) {
        let end = self.offset + output.len();
        assert!(end <= self.bytes.len(), "fixed RNG exhausted");
        output.copy_from_slice(&self.bytes[self.offset..end]);
        self.offset = end;
    }
}

impl TryRng for FixedCryptoRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut output = [0_u8; 4];
        self.take(&mut output);
        Ok(u32::from_le_bytes(output))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut output = [0_u8; 8];
        self.take(&mut output);
        Ok(u64::from_le_bytes(output))
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        self.take(output);
        Ok(())
    }
}

impl TryCryptoRng for FixedCryptoRng {}

const KEK: &str = "255e0d1c07b646dfb3134cc843ba8aa71f025b7c0838251f";
const IV: &str = "5dd4cbfc96f5453b";
const INPUT: &str = "2923bf85e06dd6ae529149f1f1bae9eab3a7da3d860d3e98";
const WRAPPED: &str =
    "690107618ef092b3b48ca1796b234ae9fa33ebb4159604037db5d6a84eb3aac2768c632775a467d4";

#[test]
fn bouncy_castle_explicit_iv_vector() {
    let kek = hex(KEK);
    let iv: [u8; 8] = hex(IV).try_into().unwrap();
    let input = hex(INPUT);
    let expected = hex(WRAPPED);
    let params = DesEdeWrapParams::with_iv(DesEdeParams::new(&kek).unwrap(), iv);
    let mut wrapper = DesEdeWrapEngine::new(FixedCryptoRng::new(Vec::new()));

    KeyWrapInit::init(&mut wrapper, WrapDirection::Wrap, &params).unwrap();
    let mut output = vec![0_u8; wrapper.wrapped_len(input.len()).unwrap()];
    let written = wrapper.wrap_into(&input, &mut output).unwrap();

    assert_eq!(written, expected.len());
    assert_eq!(output, expected);
}

#[test]
fn generated_iv_matches_bouncy_castle_vector_and_unwraps() {
    let kek = hex(KEK);
    let iv = hex(IV);
    let input = hex(INPUT);
    let expected = hex(WRAPPED);
    let wrap_params = DesEdeWrapParams::new(DesEdeParams::new(&kek).unwrap());
    let mut wrapper = DesEdeWrapEngine::new(FixedCryptoRng::new(iv));

    KeyWrapInit::init(&mut wrapper, WrapDirection::Wrap, &wrap_params).unwrap();
    let mut wrapped = vec![0_u8; wrapper.wrapped_len(input.len()).unwrap()];
    let wrapped_len = wrapper.wrap_into(&input, &mut wrapped).unwrap();
    wrapped.truncate(wrapped_len);
    assert_eq!(wrapped, expected);

    let unwrap_params = DesEdeWrapParams::new(DesEdeParams::new(&kek).unwrap());
    let mut unwrapper = DesEdeWrapEngine::new(FixedCryptoRng::new(Vec::new()));
    KeyWrapInit::init(&mut unwrapper, WrapDirection::Unwrap, &unwrap_params).unwrap();
    let mut recovered = vec![0_u8; unwrapper.max_unwrapped_len(expected.len()).unwrap()];
    let recovered_len = unwrapper.unwrap_into(&expected, &mut recovered).unwrap();
    recovered.truncate(recovered_len);

    assert_eq!(recovered, input);
}

#[test]
fn initialized_engine_supports_dynamic_dispatch() {
    let kek = hex(KEK);
    let params = DesEdeWrapParams::new(DesEdeParams::new(&kek).unwrap());
    let mut concrete = DesEdeWrapEngine::new(FixedCryptoRng::new(hex(IV)));
    KeyWrapInit::init(&mut concrete, WrapDirection::Wrap, &params).unwrap();
    let mut wrapper: Box<dyn KeyWrap<Error = DesEdeWrapError>> = Box::new(concrete);
    let input = hex(INPUT);
    let mut output = vec![0_u8; wrapper.wrapped_len(input.len()).unwrap()];

    assert_eq!(wrapper.algorithm_name(), "DESede");
    assert_eq!(wrapper.wrap_into(&input, &mut output).unwrap(), 40);
    assert_eq!(output, hex(WRAPPED));
}

#[test]
fn two_key_triple_des_round_trips() {
    let kek = hex("0123456789abcdeffedcba9876543210");
    let input = hex("00112233445566778899aabbccddeeff");
    let wrap_params = DesEdeWrapParams::new(DesEdeParams::new(&kek).unwrap());
    let mut wrapper = DesEdeWrapEngine::new(FixedCryptoRng::new(hex(IV)));
    KeyWrapInit::init(&mut wrapper, WrapDirection::Wrap, &wrap_params).unwrap();
    let mut wrapped = vec![0_u8; wrapper.wrapped_len(input.len()).unwrap()];
    wrapper.wrap_into(&input, &mut wrapped).unwrap();

    let unwrap_params = DesEdeWrapParams::new(DesEdeParams::new(&kek).unwrap());
    let mut unwrapper = DesEdeWrapEngine::new(FixedCryptoRng::new(Vec::new()));
    KeyWrapInit::init(&mut unwrapper, WrapDirection::Unwrap, &unwrap_params).unwrap();
    let mut recovered = vec![0_u8; unwrapper.max_unwrapped_len(wrapped.len()).unwrap()];
    let written = unwrapper.unwrap_into(&wrapped, &mut recovered).unwrap();

    assert_eq!(written, input.len());
    assert_eq!(recovered, input);
}

#[test]
fn unwrap_rejects_tampering_without_exposing_key_material() {
    let kek = hex(KEK);
    let mut wrapped = hex(WRAPPED);
    wrapped[20] ^= 0x01;
    let params = DesEdeWrapParams::new(DesEdeParams::new(&kek).unwrap());
    let mut unwrapper = DesEdeWrapEngine::new(FixedCryptoRng::new(Vec::new()));
    KeyWrapInit::init(&mut unwrapper, WrapDirection::Unwrap, &params).unwrap();
    let mut output = [0xa5_u8; 24];

    assert!(matches!(
        unwrapper.unwrap_into(&wrapped, &mut output),
        Err(WrapError::IntegrityCheckFailed)
    ));
    assert_eq!(output, [0xa5; 24]);
}

#[test]
fn sizing_direction_and_output_errors_are_reported() {
    let kek = hex(KEK);
    let wrap_params = DesEdeWrapParams::new(DesEdeParams::new(&kek).unwrap());
    let mut wrapper = DesEdeWrapEngine::new(FixedCryptoRng::new(hex(IV)));

    assert_eq!(wrapper.wrapped_len(0).unwrap(), 16);
    assert_eq!(wrapper.wrapped_len(24).unwrap(), 40);
    assert_eq!(wrapper.max_unwrapped_len(40).unwrap(), 24);
    assert!(matches!(
        wrapper.wrapped_len(7),
        Err(WrapError::WrapDataLength)
    ));
    assert!(matches!(
        wrapper.max_unwrapped_len(8),
        Err(WrapError::UnwrapDataLength)
    ));
    assert!(matches!(
        wrapper.max_unwrapped_len(39),
        Err(WrapError::UnwrapDataLength)
    ));
    assert!(matches!(
        wrapper.wrap_into(&[0_u8; 8], &mut [0_u8; 24]),
        Err(WrapError::Uninitialised)
    ));

    KeyWrapInit::init(&mut wrapper, WrapDirection::Wrap, &wrap_params).unwrap();
    assert!(matches!(
        wrapper.wrap_into(&[0_u8; 8], &mut [0_u8; 23]),
        Err(WrapError::OutputBufferTooShort {
            required: 24,
            available: 23,
        })
    ));
    assert!(matches!(
        wrapper.unwrap_into(&[0_u8; 24], &mut [0_u8; 8]),
        Err(WrapError::NotForUnwrapping)
    ));

    let unwrap_params = DesEdeWrapParams::new(DesEdeParams::new(&kek).unwrap());
    KeyWrapInit::init(&mut wrapper, WrapDirection::Unwrap, &unwrap_params).unwrap();
    assert!(matches!(
        wrapper.wrap_into(&[], &mut [0_u8; 16]),
        Err(WrapError::NotForWrapping)
    ));
    assert!(matches!(
        wrapper.unwrap_into(&[0_u8; 24], &mut [0_u8; 7]),
        Err(WrapError::OutputBufferTooShort {
            required: 8,
            available: 7,
        })
    ));
}

#[test]
fn external_iv_is_rejected_for_unwrap() {
    let kek = hex(KEK);
    let iv: [u8; 8] = hex(IV).try_into().unwrap();
    let params = DesEdeWrapParams::with_iv(DesEdeParams::new(&kek).unwrap(), iv);
    let mut wrapper = DesEdeWrapEngine::new(FixedCryptoRng::new(Vec::new()));

    assert!(matches!(
        KeyWrapInit::init(&mut wrapper, WrapDirection::Unwrap, &params),
        Err(WrapError::IvNotAllowedForUnwrap)
    ));
}

#[test]
fn parameter_debug_output_redacts_key_and_iv_material() {
    let kek = hex(KEK);
    let iv: [u8; 8] = hex(IV).try_into().unwrap();
    let params = DesEdeWrapParams::with_iv(DesEdeParams::new(&kek).unwrap(), iv);
    let debug = format!("{params:?}");

    assert_eq!(debug, "DesEdeWrapParams { iv_supplied: true }");
    assert!(!debug.contains(IV));
    assert!(!debug.contains(KEK));
}
