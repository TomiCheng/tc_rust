use tc_cipher::CipherDirection;

use super::fixed::{FixedRsaCoreEngine, validate};
use super::{LIMB_BITS, bit_length, is_odd, is_zero, limbs_for_bits};
use crate::{Rsa, RsaKeyRef as Key};
use crate::{RsaError, RsaKeyRef};

#[test]
fn limb_count_rounds_up() {
    assert_eq!(limbs_for_bits(0), 0);
    assert_eq!(limbs_for_bits(1), 1);
    assert_eq!(limbs_for_bits(LIMB_BITS), 1);
    assert_eq!(limbs_for_bits(LIMB_BITS + 1), 2);
    assert_eq!(limbs_for_bits(2048), 2048 / LIMB_BITS);
}

#[test]
fn bit_length_ignores_leading_zeros() {
    assert_eq!(bit_length(&[]), 0);
    assert_eq!(bit_length(&[0, 0, 0]), 0);
    assert_eq!(bit_length(&[1]), 1);
    assert_eq!(bit_length(&[0xff]), 8);
    assert_eq!(bit_length(&[0x00, 0x05]), bit_length(&[0x05]));
    assert_eq!(bit_length(&[0x01, 0x00]), 9);
    assert_eq!(bit_length(&[0x00, 0x80, 0x00]), 16);
}

#[test]
fn zero_and_parity_follow_the_byte_contract() {
    assert!(is_zero(&[]));
    assert!(is_zero(&[0, 0]));
    assert!(!is_zero(&[0, 1]));

    assert!(!is_odd(&[]));
    assert!(!is_odd(&[0]));
    assert!(is_odd(&[3]));
    assert!(!is_odd(&[0xff, 0x02]));
    assert!(is_odd(&[0x00, 0x01]));
}

/// 一組最小的合法值：模數 4087 = 0x0ff7，公開指數 7。
const MODULUS: [u8; 2] = [0x0f, 0xf7];
const EXPONENT: [u8; 1] = [7];

#[test]
fn accepts_odd_modulus_with_odd_exponent() {
    assert_eq!(
        validate(&RsaKeyRef::new(false, &MODULUS, &EXPONENT)),
        Ok(12)
    );
    assert_eq!(validate(&RsaKeyRef::new(true, &MODULUS, &EXPONENT)), Ok(12));
}

#[test]
fn leading_zeros_do_not_change_the_verdict() {
    let padded = [0x00, 0x00, 0x0f, 0xf7];
    assert_eq!(
        validate(&RsaKeyRef::new(false, &padded, &[0x00, 0x07])),
        Ok(12)
    );
}

#[test]
fn rejects_a_zero_or_even_modulus() {
    assert_eq!(
        validate(&RsaKeyRef::new(false, &[], &EXPONENT)),
        Err(RsaError::InvalidModulus)
    );
    assert_eq!(
        validate(&RsaKeyRef::new(false, &[0, 0], &EXPONENT)),
        Err(RsaError::InvalidModulus)
    );
    assert_eq!(
        validate(&RsaKeyRef::new(false, &[0x0f, 0xf6], &EXPONENT)),
        Err(RsaError::EvenModulus)
    );
}

#[test]
fn exponent_errors_depend_on_whether_the_key_is_private() {
    assert_eq!(
        validate(&RsaKeyRef::new(false, &MODULUS, &[0])),
        Err(RsaError::InvalidExponent)
    );
    assert_eq!(
        validate(&RsaKeyRef::new(true, &MODULUS, &[0])),
        Err(RsaError::InvalidPrivateExponent)
    );
    assert_eq!(
        validate(&RsaKeyRef::new(false, &MODULUS, &[4])),
        Err(RsaError::EvenPublicExponent)
    );
    assert_eq!(
        validate(&RsaKeyRef::new(true, &MODULUS, &[4])),
        Err(RsaError::InvalidPrivateExponent)
    );
}

/// 以 4087 = 0x0ff7 為模數建一個單 limb 的核心。
fn engine(direction: CipherDirection) -> FixedRsaCoreEngine<1> {
    FixedRsaCoreEngine::new(direction, &RsaKeyRef::new(false, &MODULUS, &EXPONENT)).unwrap()
}

#[test]
fn convert_input_rejects_the_trivial_and_out_of_range_values() {
    let engine = engine(CipherDirection::Encrypt);

    assert_eq!(
        Rsa::<Key>::convert_input(&engine, &[0]),
        Err(RsaError::InputTooSmall)
    );
    assert_eq!(
        Rsa::<Key>::convert_input(&engine, &[1]),
        Err(RsaError::InputTooSmall)
    );
    assert_eq!(
        Rsa::<Key>::convert_input(&engine, &[0x0f, 0xf6]),
        Err(RsaError::InputTooLarge)
    );
    assert_eq!(
        Rsa::<Key>::convert_input(&engine, &[0x0f, 0xf7]),
        Err(RsaError::InputTooLarge)
    );
    assert!(Rsa::<Key>::convert_input(&engine, &[2]).is_ok());
}

#[test]
fn convert_output_pads_when_encrypting_and_trims_when_decrypting() {
    let value = Rsa::<Key>::convert_input(&engine(CipherDirection::Encrypt), &[2]).unwrap();

    let mut buffer = [0xaa_u8; 4];
    assert_eq!(
        Rsa::<Key>::convert_output(&engine(CipherDirection::Encrypt), &value, &mut buffer),
        Ok(2)
    );
    assert_eq!(buffer[..2], [0x00, 0x02]);

    let mut buffer = [0xaa_u8; 4];
    assert_eq!(
        Rsa::<Key>::convert_output(&engine(CipherDirection::Decrypt), &value, &mut buffer),
        Ok(1)
    );
    assert_eq!(buffer[0], 0x02);
}

#[test]
fn convert_output_reports_a_short_buffer() {
    let value = Rsa::<Key>::convert_input(&engine(CipherDirection::Encrypt), &[2]).unwrap();

    assert_eq!(
        Rsa::<Key>::convert_output(&engine(CipherDirection::Encrypt), &value, &mut [0_u8; 1]),
        Err(RsaError::OutputTooShort)
    );
}

#[test]
fn public_and_private_exponents_round_trip() {
    // 4087 = 61 * 67，λ(4087) = lcm(60, 66) = 660，7 * 2263 ≡ 1 (mod 660)。
    const PRIVATE_EXPONENT: [u8; 2] = [0x08, 0xd7];

    let mut public = FixedRsaCoreEngine::<1>::new(
        CipherDirection::Encrypt,
        &Key::new(false, &MODULUS, &EXPONENT),
    )
    .unwrap();
    let mut private = FixedRsaCoreEngine::<1>::new(
        CipherDirection::Decrypt,
        &Key::new(true, &MODULUS, &PRIVATE_EXPONENT),
    )
    .unwrap();

    for message in [&[2_u8][..], &[42][..], &[0x0f, 0xf5][..]] {
        let plain = Rsa::<Key>::convert_input(&public, message).unwrap();
        let cipher = Rsa::<Key>::process_block(&mut public, &plain).unwrap();
        let recovered = Rsa::<Key>::process_block(&mut private, &cipher).unwrap();
        assert_eq!(recovered, plain);

        let mut output = [0_u8; 2];
        let length = Rsa::<Key>::convert_output(&private, &recovered, &mut output).unwrap();
        assert_eq!(&output[..length], message);
    }
}
