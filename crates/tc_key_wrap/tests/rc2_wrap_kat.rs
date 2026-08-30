//! CMS RC2 key-wrap tests using the RFC 3217 and Bouncy Castle vector.

use core::convert::Infallible;

use rand_core::{TryCryptoRng, TryRng};
use tc_block_cipher::Rc2Params;
use tc_cipher_core::{KeyWrap, KeyWrapInit, WrapDirection};
use tc_key_wrap::{Rc2WrapEngine, Rc2WrapError, Rc2WrapParams, WrapError};

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

const KEK: &str = "fd04fd08060707fb0003fefffd02fe05";
const IV: &str = "c7d90059b29e97f7";
const PADDING: &str = "4845cce7fd1250";
const INPUT: &str = "b70a25fbc9d86a86050ce0d711ead4d9";
const WRAPPED: &str =
    "70e699fb5701f7833330fb71e87c85a420bdc99af05d22af5a0e48d35f3138986cbaafb4b28d4f35";

fn rfc_key_params() -> Rc2Params {
    Rc2Params::with_effective_key_bits(&hex(KEK), 40).unwrap()
}

#[test]
fn rfc3217_explicit_iv_vector() {
    let iv: [u8; 8] = hex(IV).try_into().unwrap();
    let input = hex(INPUT);
    let expected = hex(WRAPPED);
    let params = Rc2WrapParams::with_iv(rfc_key_params(), iv);
    let mut wrapper = Rc2WrapEngine::new(FixedCryptoRng::new(hex(PADDING)));

    KeyWrapInit::init(&mut wrapper, WrapDirection::Wrap, &params).unwrap();
    let mut output = vec![0_u8; wrapper.wrapped_len(input.len()).unwrap()];
    let written = wrapper.wrap_into(&input, &mut output).unwrap();

    assert_eq!(written, expected.len());
    assert_eq!(output, expected);
}

#[test]
fn generated_iv_matches_rfc3217_vector_and_unwraps() {
    let input = hex(INPUT);
    let expected = hex(WRAPPED);
    let mut random = hex(IV);
    random.extend_from_slice(&hex(PADDING));
    let wrap_params = Rc2WrapParams::new(rfc_key_params());
    let mut wrapper = Rc2WrapEngine::new(FixedCryptoRng::new(random));

    KeyWrapInit::init(&mut wrapper, WrapDirection::Wrap, &wrap_params).unwrap();
    let mut wrapped = vec![0_u8; wrapper.wrapped_len(input.len()).unwrap()];
    let wrapped_len = wrapper.wrap_into(&input, &mut wrapped).unwrap();
    wrapped.truncate(wrapped_len);
    assert_eq!(wrapped, expected);

    let unwrap_params = Rc2WrapParams::new(rfc_key_params());
    let mut unwrapper = Rc2WrapEngine::new(FixedCryptoRng::new(Vec::new()));
    KeyWrapInit::init(&mut unwrapper, WrapDirection::Unwrap, &unwrap_params).unwrap();
    let mut recovered = vec![0_u8; unwrapper.max_unwrapped_len(expected.len()).unwrap()];
    let recovered_len = unwrapper.unwrap_into(&expected, &mut recovered).unwrap();
    recovered.truncate(recovered_len);

    assert_eq!(recovered, input);
}

#[test]
fn variable_length_keys_round_trip() {
    for length in [0, 1, 7, 8, 15, 16, 31, 255] {
        let input: Vec<u8> = (0..length).map(|index| index as u8).collect();
        let wrap_params =
            Rc2WrapParams::new(Rc2Params::with_effective_key_bits(&[0x5a; 16], 128).unwrap());
        let mut wrapper = Rc2WrapEngine::new(FixedCryptoRng::new(vec![0xa5; 16]));
        KeyWrapInit::init(&mut wrapper, WrapDirection::Wrap, &wrap_params).unwrap();
        let mut wrapped = vec![0_u8; wrapper.wrapped_len(input.len()).unwrap()];
        wrapper.wrap_into(&input, &mut wrapped).unwrap();

        let unwrap_params =
            Rc2WrapParams::new(Rc2Params::with_effective_key_bits(&[0x5a; 16], 128).unwrap());
        let mut unwrapper = Rc2WrapEngine::new(FixedCryptoRng::new(Vec::new()));
        KeyWrapInit::init(&mut unwrapper, WrapDirection::Unwrap, &unwrap_params).unwrap();
        let mut recovered = vec![0_u8; unwrapper.max_unwrapped_len(wrapped.len()).unwrap()];
        let written = unwrapper.unwrap_into(&wrapped, &mut recovered).unwrap();

        assert_eq!(written, input.len(), "length {length}");
        assert_eq!(&recovered[..written], input, "length {length}");
    }
}

#[test]
fn initialized_engine_supports_dynamic_dispatch() {
    let params = Rc2WrapParams::new(rfc_key_params());
    let mut random = hex(IV);
    random.extend_from_slice(&hex(PADDING));
    let mut concrete = Rc2WrapEngine::new(FixedCryptoRng::new(random));
    KeyWrapInit::init(&mut concrete, WrapDirection::Wrap, &params).unwrap();
    let mut wrapper: Box<dyn KeyWrap<Error = Rc2WrapError>> = Box::new(concrete);
    let input = hex(INPUT);
    let mut output = vec![0_u8; wrapper.wrapped_len(input.len()).unwrap()];

    assert_eq!(wrapper.algorithm_name(), "RC2");
    assert_eq!(wrapper.wrap_into(&input, &mut output).unwrap(), 40);
    assert_eq!(output, hex(WRAPPED));
}

#[test]
fn unwrap_rejects_tampering_without_exposing_key_material() {
    let mut wrapped = hex(WRAPPED);
    wrapped[20] ^= 0x01;
    let params = Rc2WrapParams::new(rfc_key_params());
    let mut unwrapper = Rc2WrapEngine::new(FixedCryptoRng::new(Vec::new()));
    KeyWrapInit::init(&mut unwrapper, WrapDirection::Unwrap, &params).unwrap();
    let mut output = [0xa5_u8; 23];

    assert!(matches!(
        unwrapper.unwrap_into(&wrapped, &mut output),
        Err(WrapError::IntegrityCheckFailed)
    ));
    assert_eq!(output, [0xa5; 23]);
}

#[test]
fn sizing_direction_and_output_errors_are_reported() {
    let params = Rc2WrapParams::new(rfc_key_params());
    let mut wrapper = Rc2WrapEngine::new(FixedCryptoRng::new(vec![0xa5; 32]));

    assert_eq!(wrapper.wrapped_len(0).unwrap(), 24);
    assert_eq!(wrapper.wrapped_len(7).unwrap(), 24);
    assert_eq!(wrapper.wrapped_len(8).unwrap(), 32);
    assert_eq!(wrapper.wrapped_len(16).unwrap(), 40);
    assert_eq!(wrapper.wrapped_len(255).unwrap(), 272);
    assert_eq!(wrapper.max_unwrapped_len(24).unwrap(), 7);
    assert_eq!(wrapper.max_unwrapped_len(40).unwrap(), 23);
    assert!(matches!(
        wrapper.wrapped_len(256),
        Err(WrapError::WrapDataLength)
    ));
    assert!(matches!(
        wrapper.max_unwrapped_len(16),
        Err(WrapError::UnwrapDataLength)
    ));
    assert!(matches!(
        wrapper.max_unwrapped_len(39),
        Err(WrapError::UnwrapDataLength)
    ));
    assert!(matches!(
        wrapper.max_unwrapped_len(280),
        Err(WrapError::UnwrapDataLength)
    ));
    assert!(matches!(
        wrapper.wrap_into(&[0_u8; 8], &mut [0_u8; 32]),
        Err(WrapError::Uninitialised)
    ));

    KeyWrapInit::init(&mut wrapper, WrapDirection::Wrap, &params).unwrap();
    assert!(matches!(
        wrapper.wrap_into(&[0_u8; 8], &mut [0_u8; 31]),
        Err(WrapError::OutputBufferTooShort {
            required: 32,
            available: 31,
        })
    ));
    assert!(matches!(
        wrapper.unwrap_into(&[0_u8; 24], &mut [0_u8; 7]),
        Err(WrapError::NotForUnwrapping)
    ));

    let unwrap_params = Rc2WrapParams::new(rfc_key_params());
    KeyWrapInit::init(&mut wrapper, WrapDirection::Unwrap, &unwrap_params).unwrap();
    assert!(matches!(
        wrapper.wrap_into(&[], &mut [0_u8; 24]),
        Err(WrapError::NotForWrapping)
    ));
    assert!(matches!(
        wrapper.unwrap_into(&[0_u8; 24], &mut [0_u8; 6]),
        Err(WrapError::OutputBufferTooShort {
            required: 7,
            available: 6,
        })
    ));
}

#[test]
fn external_iv_is_rejected_for_unwrap() {
    let iv: [u8; 8] = hex(IV).try_into().unwrap();
    let params = Rc2WrapParams::with_iv(rfc_key_params(), iv);
    let mut wrapper = Rc2WrapEngine::new(FixedCryptoRng::new(Vec::new()));

    assert!(matches!(
        KeyWrapInit::init(&mut wrapper, WrapDirection::Unwrap, &params),
        Err(WrapError::IvNotAllowedForUnwrap)
    ));
}

#[test]
fn parameter_debug_output_redacts_key_and_iv_material() {
    let iv: [u8; 8] = hex(IV).try_into().unwrap();
    let params = Rc2WrapParams::with_iv(rfc_key_params(), iv);
    let debug = format!("{params:?}");

    assert_eq!(debug, "Rc2WrapParams { iv_supplied: true }");
    assert!(!debug.contains(IV));
    assert!(!debug.contains(KEK));
}
