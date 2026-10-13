//! What the tests share: the RSA key of Bouncy Castle's `RsaTest`, and
//! the raw engine to make blocks the encoding did not.

#![allow(dead_code)]

use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_rsa_v2::{RsaEngine, RsaKey, RsaKeyOwned};

/// The 1024-bit key of Bouncy Castle's `RsaTest`; the public exponent is 17.
pub const MODULUS: &str = concat!(
    "b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6",
    "f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdb",
    "f3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26",
    "c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5",
);
pub const PRIVATE_EXPONENT: &str = concat!(
    "92e08f83cc9920746989ca5034dcb384a094fb9c5a6288fcc4304424ab8f5638",
    "8f72652d8fafc65a4b9020896f2cde297080f2a540e7b7ce5af0b3446e1258d1",
    "dd7f245cf54124b4c6e17da21b90a0ebd22605e6f45c9f136d7a13eaac1c0f74",
    "87de8bd6d924972408ebb58af71e76fd7b012a8d0e165f3ae2e5077a8648e619",
);

pub fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

/// `text`, in hexadecimal, as an integer.
pub fn int(text: &str) -> PaddedBigUint {
    let Ok(value) = PaddedBigUint::from_be(&hex(text));
    value
}

/// A key of `modulus` and `exponent`, in hexadecimal.
pub fn key_of(private: bool, modulus: &str, exponent: &str) -> RsaKey {
    RsaKey::from(RsaKeyOwned::new(private, int(modulus), int(exponent)))
}

/// The key of `RsaTest`, private or public.
pub fn key(private: bool) -> RsaKey {
    let exponent = if private { PRIVATE_EXPONENT } else { "11" };
    key_of(private, MODULUS, exponent)
}

/// `block` raised to the exponent of `key` by the engine alone, without
/// padding, for a key of the other kind to decrypt.
pub fn raw(key: &RsaKey, block: &[u8]) -> Vec<u8> {
    let mut engine = RsaEngine::new();
    engine.init(CipherDirection::Decrypt, key).unwrap();
    let mut output = vec![0; engine.output_block_size()];
    let written = engine.process_block(block, &mut output).unwrap();
    assert_eq!(written, output.len());
    output
}
