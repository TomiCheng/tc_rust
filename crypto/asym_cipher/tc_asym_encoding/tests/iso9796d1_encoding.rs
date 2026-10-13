//! ISO 9796-1 over RSA, with the vectors of Bouncy Castle's `ISO9796Test`.

#![cfg(feature = "iso9796")]

mod common;

use common::{Engine, Key, U1024, hex, key, key_of, raw};
use rand::SeedableRng;
use rand::rngs::StdRng;
use tc_asym_cipher::{
    AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection, KeyPairGenerator,
    KeyPairGeneratorInit,
};
use tc_asym_encoding::{EncodingError, Iso9796d1Encoding};
use tc_rsa_v2::{RsaError, RsaKeyGenerationParamsOwned, RsaKeyPairGenerator};

type Encoding = Iso9796d1Encoding<Engine, U1024>;
type Error = EncodingError<RsaError>;

/// The 513-bit key of `ISO9796Test`; the public exponent is 3.
const MOD1: &str = concat!(
    "0100000000000000000000000000000000bba2d15dbb303c8a21c5ebbcbae52b",
    "7125087920dd7cdf358ea119fd66fb064012ec8ce692f0a0b8e8321b041acd40b7",
);
const PRI1: &str = concat!(
    "2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac9f0783a49dd5f6c5af651f4c9d0dc92",
    "81c96a3f16a85f9572d7cc3f2d0f25a9dbf1149e4cdc32273faadd3fda5dcda7",
);

/// The 512-bit key of `ISO9796Test`; the public exponent is 3.
const MOD2: &str = concat!(
    "ffffff7fa27087c35ebead78412d2bdffe0301edd494df13458974ea89b36470",
    "8f7d0f5a00a50779ddf9f7d4cb80b8891324da251a860c4ec9ef288104b3858d",
);
const PRI2: &str = concat!(
    "2aaaaa9545bd6bf5e51fc7940adcdca5550080524e18cfd88b96e8d1c19de612",
    "1b13fac0eb0495d47928e047724d91d1740f6968457ce53ec8e24c9362ce84b5",
);

/// A case of `ISO9796Test`: the key, the message, its pad bits, the
/// signature Bouncy Castle makes, and the one ISO 9796-1 lists, where it
/// lists the modulus less it.
struct Case {
    modulus: &'static str,
    private_exponent: &'static str,
    message: &'static str,
    pad_bits: u8,
    signature: &'static str,
    listed: &'static str,
}

const CASES: [Case; 3] = [
    Case {
        modulus: MOD1,
        private_exponent: PRI1,
        message: "0cbbaa99887766554433221100",
        pad_bits: 4,
        signature: concat!(
            "00cf6078c272127c86b6f09f6815502544a825929de23de1d4308d165249484f",
            "1eb92b76f2371f3389fc9698fc2c7535ad329f4ea47645e9a11f249119d5246e",
            "7d",
        ),
        listed: concat!(
            "00309f873d8ded8379490f6097eaafdabc137d3ebfd8f25ab5f138d56a719cdc",
            "526bdd022ea65dabab920a81013a85d092e04d3e421caab717c90d89ea45a8d2",
            "3a",
        ),
    },
    Case {
        modulus: MOD1,
        private_exponent: PRI1,
        message: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        pad_bits: 0,
        signature: concat!(
            "00319bb9becb49f3ed1bca26d0fcf09b0b0a508e4d0bd43b350f959b72cd25b3",
            "af47d608fdcd248eada74fbe19990dbeb9bf0da4b4e1200243a14e5cab3f7e61",
            "0c",
        ),
        listed: concat!(
            "00319bb9becb49f3ed1bca26d0fcf09b0b0a508e4d0bd43b350f959b72cd25b3",
            "af47d608fdcd248eada74fbe19990dbeb9bf0da4b4e1200243a14e5cab3f7e61",
            "0c",
        ),
    },
    Case {
        modulus: MOD2,
        private_exponent: PRI2,
        message: "0112233445566778899aabbccd",
        pad_bits: 4,
        signature: concat!(
            "a71a5f845750d60682c5db79a632f4af3678d063c35fe99a2a16611608b45cc4",
            "5de208cb2115e650982eee0597a187dc2dd5901edab96b9796fa721e28656139",
        ),
        listed: concat!(
            "58e59ffb4b1fb1bcdbf8d1fe9afa3730c78a318a1134f5791b7313d480ff07ac",
            "319b068edf8f212945cb09cf33df30ace54f4a063fcca0b732f4b662dc4e2454",
        ),
    },
];

impl Case {
    fn key(&self, private: bool) -> Key {
        let exponent = if private { self.private_exponent } else { "03" };
        key_of(private, self.modulus, exponent)
    }
}

fn process<P>(
    encoding: &mut Encoding,
    direction: CipherDirection,
    key: &P,
    input: &[u8],
) -> Result<Vec<u8>, Error>
where
    Encoding: AsymmetricBlockCipherInit<P, Error = Error>,
{
    encoding.init(direction, key)?;
    let mut output = vec![0; encoding.output_block_size()];
    let length = encoding.process_block(input, &mut output)?;
    output.truncate(length);
    Ok(output)
}

fn sign<P>(encoding: &mut Encoding, key: &P, message: &[u8]) -> Result<Vec<u8>, Error>
where
    Encoding: AsymmetricBlockCipherInit<P, Error = Error>,
{
    process(encoding, CipherDirection::Encrypt, key, message)
}

fn verify<P>(encoding: &mut Encoding, key: &P, signature: &[u8]) -> Result<Vec<u8>, Error>
where
    Encoding: AsymmetricBlockCipherInit<P, Error = Error>,
{
    process(encoding, CipherDirection::Decrypt, key, signature)
}

fn encoding() -> Encoding {
    Iso9796d1Encoding::new(Engine::new())
}

#[test]
fn the_vectors_of_bouncy_castle_sign_to_their_signatures_and_back() {
    for (number, case) in CASES.iter().enumerate() {
        let mut encoding = encoding();
        encoding.set_pad_bits(case.pad_bits);
        let signature = sign(&mut encoding, &case.key(true), &hex(case.message));
        assert_eq!(signature, Ok(hex(case.signature)), "{}", number + 1);
        encoding.set_pad_bits(0);
        assert_eq!(
            verify(&mut encoding, &case.key(false), &hex(case.signature)),
            Ok(hex(case.message)),
            "{}",
            number + 1
        );
        assert_eq!(encoding.pad_bits(), case.pad_bits, "{}", number + 1);
    }
}

#[test]
fn the_signatures_iso_lists_verify_as_the_modulus_less_them() {
    for (number, case) in CASES.iter().enumerate() {
        let mut encoding = encoding();
        assert_eq!(
            verify(&mut encoding, &case.key(false), &hex(case.listed)),
            Ok(hex(case.message)),
            "{}",
            number + 1
        );
    }
}

#[test]
fn the_blocks_are_half_the_modulus_for_the_message() {
    let mut encoding = encoding();
    encoding.init(CipherDirection::Encrypt, &key(true)).unwrap();
    assert_eq!(
        (encoding.input_block_size(), encoding.output_block_size()),
        (64, 128)
    );
    encoding
        .init(CipherDirection::Decrypt, &key(false))
        .unwrap();
    assert_eq!(
        (encoding.input_block_size(), encoding.output_block_size()),
        (128, 64)
    );
}

#[test]
fn messages_of_every_length_round_trip_with_their_pad_bits() {
    let mut encoding = encoding();
    for length in 1..=64 {
        let message: Vec<u8> = (0..length as u8).map(|byte| byte ^ 0xa5).collect();
        let pad_bits = length as u8 % 8;
        encoding.set_pad_bits(pad_bits);
        let signature = sign(&mut encoding, &key(true), &message).unwrap();
        assert_eq!(
            verify(&mut encoding, &key(false), &signature),
            Ok(message),
            "{length}"
        );
        // A message that fills the half loses its mark to the forced top
        // bits, and its pad bits with it, as in Bouncy Castle.
        let expected = if length == 64 { 0 } else { pad_bits };
        assert_eq!(encoding.pad_bits(), expected, "{length}");
    }
}

#[test]
fn moduli_of_each_size_taken_round_trip_and_the_others_are_turned_down() {
    for bits in 512..528 {
        let rng = StdRng::seed_from_u64(u64::from(bits));
        let mut generator = RsaKeyPairGenerator::<U1024>::new();
        generator
            .init(RsaKeyGenerationParamsOwned::new(rng).with_strength(bits))
            .unwrap();
        let (public, private) = generator.generate_key_pair().unwrap();
        let mut encoding = encoding();
        if (3..=9).contains(&(bits % 16)) {
            assert_eq!(
                encoding.init(CipherDirection::Encrypt, &private),
                Err(EncodingError::UnsupportedKeySize),
                "{bits}"
            );
            assert_eq!(
                encoding.process_block(&[1], &mut [0; 128]),
                Err(EncodingError::NotInitialized),
                "{bits}"
            );
            continue;
        }
        encoding.init(CipherDirection::Encrypt, &private).unwrap();
        let longest = encoding.input_block_size();
        for length in [1, longest / 2, longest] {
            let message = vec![0x3c; length];
            encoding.set_pad_bits(3);
            let signature = sign(&mut encoding, &private, &message).unwrap();
            assert_eq!(
                verify(&mut encoding, &public, &signature),
                Ok(message),
                "{bits} {length}"
            );
        }
    }
}

#[test]
fn an_empty_or_too_long_message_or_too_many_pad_bits_are_turned_down() {
    let mut encoding = encoding();
    encoding.init(CipherDirection::Encrypt, &key(true)).unwrap();
    let mut output = [0; 128];
    assert_eq!(
        encoding.process_block(&[], &mut output),
        Err(EncodingError::InputTooShort)
    );
    assert_eq!(
        encoding.process_block(&[1; 65], &mut output),
        Err(EncodingError::InputTooLarge)
    );
    encoding.set_pad_bits(8);
    assert_eq!(
        encoding.process_block(&[1], &mut output),
        Err(EncodingError::InvalidPadBits)
    );
    encoding.set_pad_bits(7);
    assert_eq!(encoding.process_block(&[1], &mut output), Ok(128));
}

#[test]
fn a_block_that_ends_in_six_neither_way_fails_verification() {
    // The modulus ends in 5: a block ending in 5 leaves it ending in 0.
    let mut block = vec![0x12; 128];
    block[127] = 0x15;
    let signature = raw(&key(true), &block);
    assert_eq!(
        verify(&mut encoding(), &key(false), &signature),
        Err(EncodingError::InvalidBlock)
    );
}

#[test]
fn a_block_with_a_second_shadow_off_fails_verification() {
    let case = &CASES[0];
    let mut block = raw(&case.key(false), &hex(case.signature));
    // A shadow byte well before where the message starts, at 39.
    block[21] ^= 0x01;
    let forged = raw(&case.key(true), &block);
    assert_eq!(
        verify(&mut encoding(), &case.key(false), &forged),
        Err(EncodingError::InvalidBlock)
    );
}

#[test]
fn a_block_too_short_for_its_pairs_fails_verification() {
    // Ends in six, but leaves 63 bytes, below the 128 of the pairs.
    let mut block = vec![0x00; 128];
    block[65..].fill(0x5a);
    block[127] = 0x56;
    let signature = raw(&key(true), &block);
    assert_eq!(
        verify(&mut encoding(), &key(false), &signature),
        Err(EncodingError::InvalidBlock)
    );
}

#[test]
fn an_encoding_not_yet_initialized_processes_nothing() {
    let mut encoding = encoding();
    assert_eq!(
        (encoding.input_block_size(), encoding.output_block_size()),
        (0, 0)
    );
    assert_eq!(
        encoding.process_block(&[1], &mut [0; 128]),
        Err(EncodingError::NotInitialized)
    );
}

#[test]
fn an_output_shorter_than_the_output_block_is_turned_down() {
    let mut encoding = encoding();
    encoding.init(CipherDirection::Encrypt, &key(true)).unwrap();
    assert_eq!(
        encoding.process_block(&[1], &mut [0; 127]),
        Err(EncodingError::OutputTooShort)
    );
    let signature = sign(&mut encoding, &key(true), &[1]).unwrap();
    encoding
        .init(CipherDirection::Decrypt, &key(false))
        .unwrap();
    assert_eq!(
        encoding.process_block(&signature, &mut [0; 63]),
        Err(EncodingError::OutputTooShort)
    );
    assert_eq!(encoding.process_block(&signature, &mut [0; 64]), Ok(1));
}

#[test]
fn the_encoding_is_named_after_its_engine() {
    assert_eq!(encoding().to_string(), "RSA/ISO9796-1Padding");
}

#[test]
fn the_engine_comes_back_out_of_the_encoding() {
    let mut encoding = encoding();
    encoding.init(CipherDirection::Encrypt, &key(true)).unwrap();
    // The engine decrypts, whose input block is the whole modulus.
    assert_eq!(encoding.underlying_cipher().input_block_size(), 128);
    assert_eq!(encoding.into_inner().output_block_size(), 128);
}
