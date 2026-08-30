//! RFC 3211 wrapping tests using Bouncy Castle's fixed-random vectors.

use core::convert::Infallible;

use rand_core::{TryCryptoRng, TryRng};
use tc_block_cipher::{
    AesEngine, AesParams, AriaEngine, AriaParams, DesEdeEngine, DesEdeParams, DesEngine, DesParams,
};
use tc_cipher_core::{KeyWrap, KeyWrapInit, WrapDirection};
use tc_key_wrap::{Rfc3211Params, Rfc3211WrapEngine, WrapError};

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

macro_rules! wrap_kat {
    ($name:ident, $engine:ty, $params:ty, $key:expr, $iv:expr, $random:expr, $input:expr, $expected:expr) => {
        #[test]
        fn $name() {
            let key = hex($key);
            let iv = hex($iv);
            let input = hex($input);
            let expected = hex($expected);
            let rng = FixedCryptoRng::new(hex($random));
            let mut wrapper = Rfc3211WrapEngine::new(<$engine>::new(), rng);
            let params = Rfc3211Params::new(<$params>::new(&key).unwrap(), &iv);

            wrapper.init(WrapDirection::Wrap, &params).unwrap();
            let mut output = vec![0_u8; wrapper.wrapped_len(input.len()).unwrap()];
            let written = wrapper.wrap_into(&input, &mut output).unwrap();

            assert_eq!(written, output.len());
            assert_eq!(output, expected);

            let mut unwrapper =
                Rfc3211WrapEngine::new(<$engine>::new(), FixedCryptoRng::new(Vec::new()));
            unwrapper.init(WrapDirection::Unwrap, &params).unwrap();
            let mut recovered = vec![0_u8; unwrapper.max_unwrapped_len(expected.len()).unwrap()];
            let recovered_len = unwrapper.unwrap_into(&expected, &mut recovered).unwrap();

            assert_eq!(recovered_len, input.len());
            assert_eq!(&recovered[..recovered_len], input);
        }
    };
}

wrap_kat!(
    des_bc_vector,
    DesEngine,
    DesParams,
    "D1DAA78615F287E6",
    "EFE598EF21B33D6D",
    "C436F541",
    "8C627C897323A2F8",
    "B81B2565EE373CA6DEDCA26A178B0C10"
);

wrap_kat!(
    des_ede_bc_vector,
    DesEdeEngine,
    DesEdeParams,
    "6A8970BF68C92CAEA84A8DF28510858607126380CC47AB2D",
    "BAF1CA7931213C4E",
    "FA060A45",
    "8C637D887223A2F965B566EB014B0FA5D52300A3F7EA40FFFC577203C71BAF3B",
    "C03C514ABDB9E2C5AAC038572B5E24553876B377AAFB82ECA5A9D73F8AB143D9EC74E6CAD7DB260C"
);

wrap_kat!(
    aes_bc_vector,
    AesEngine,
    AesParams,
    "000102030405060708090A0B0C0D0E0F",
    "000102030405060708090A0B0C0D0E0F",
    "9688DF2AF1B7B1AC9688DF2A",
    "00112233445566778899AABBCCDDEEFF",
    "7C8798DFC802553B3F00BB4315E3A087322725C92398B9C112C74D0925C63B61"
);

wrap_kat!(
    aria_bc_vector,
    AriaEngine,
    AriaParams,
    "000102030405060708090A0B0C0D0E0F",
    "000102030405060708090A0B0C0D0E0F",
    "9688DF2AF1B7B1AC9688DF2A",
    "00112233445566778899AABBCCDDEEFF",
    "9B2D3CAC0ACF9D4BDE7C1BDB0313FBEF931F025ACC77BF57D3D1CABC88B514D0"
);

#[test]
fn sizing_direction_and_output_errors_are_reported() {
    let key = hex("000102030405060708090A0B0C0D0E0F");
    let iv = hex("000102030405060708090A0B0C0D0E0F");
    let params = Rfc3211Params::new(AesParams::new(&key).unwrap(), &iv);
    let mut wrapper = Rfc3211WrapEngine::new(AesEngine::new(), FixedCryptoRng::new(vec![0; 32]));

    assert_eq!(wrapper.wrapped_len(0).unwrap(), 32);
    assert_eq!(wrapper.wrapped_len(28).unwrap(), 32);
    assert_eq!(wrapper.wrapped_len(29).unwrap(), 48);
    assert_eq!(wrapper.max_unwrapped_len(32).unwrap(), 28);
    assert!(matches!(
        wrapper.wrapped_len(256),
        Err(WrapError::WrapDataLength)
    ));
    assert!(matches!(
        wrapper.max_unwrapped_len(16),
        Err(WrapError::UnwrapDataLength)
    ));
    assert!(matches!(
        wrapper.max_unwrapped_len(33),
        Err(WrapError::UnwrapDataLength)
    ));
    assert!(matches!(
        wrapper.wrap_into(&[], &mut [0_u8; 32]),
        Err(WrapError::Uninitialised)
    ));
    assert!(matches!(
        wrapper.unwrap_into(&[0_u8; 32], &mut [0_u8; 28]),
        Err(WrapError::Uninitialised)
    ));

    wrapper.init(WrapDirection::Wrap, &params).unwrap();
    assert!(matches!(
        wrapper.wrap_into(&[0_u8; 16], &mut [0_u8; 31]),
        Err(WrapError::OutputBufferTooShort {
            required: 32,
            available: 31,
        })
    ));
    assert!(matches!(
        wrapper.unwrap_into(&[0_u8; 32], &mut [0_u8; 28]),
        Err(WrapError::NotForUnwrapping)
    ));

    wrapper.init(WrapDirection::Unwrap, &params).unwrap();
    assert!(matches!(
        wrapper.wrap_into(&[], &mut [0_u8; 32]),
        Err(WrapError::NotForWrapping)
    ));
    assert!(matches!(
        wrapper.unwrap_into(&[0_u8; 32], &mut [0_u8; 27]),
        Err(WrapError::OutputBufferTooShort {
            required: 28,
            available: 27,
        })
    ));
}

#[test]
fn unwrap_rejects_tampering_without_exposing_unauthenticated_key_material() {
    let key = hex("000102030405060708090A0B0C0D0E0F");
    let iv = hex("000102030405060708090A0B0C0D0E0F");
    let params = Rfc3211Params::new(AesParams::new(&key).unwrap(), &iv);
    let mut wrapped = hex("7C8798DFC802553B3F00BB4315E3A087322725C92398B9C112C74D0925C63B61");
    wrapped[20] ^= 0x01;

    let mut unwrapper = Rfc3211WrapEngine::new(AesEngine::new(), FixedCryptoRng::new(Vec::new()));
    unwrapper.init(WrapDirection::Unwrap, &params).unwrap();
    let mut output = [0xa5_u8; 28];

    assert!(matches!(
        unwrapper.unwrap_into(&wrapped, &mut output),
        Err(WrapError::IntegrityCheckFailed)
    ));
    assert_eq!(output, [0xa5; 28]);
}
