//! PKCS#1 v1.5 over RSA, with the key, the message and the bad blocks of
//! Bouncy Castle's `RsaTest`.

mod common;

use common::{Engine, INPUT, Key, hex, key, raw};
use rand::SeedableRng;
use rand::rngs::StdRng;
use rand_core::{CryptoRng, Rng, TryCryptoRng, TryRng};
use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
use tc_asym_encoding::{EncodingError, Pkcs1Encoding};
use tc_rsa_v2::RsaError;

type Error = EncodingError<RsaError>;

/// `INPUT` padded as block type 1 and raised to the private exponent,
/// worked out apart from the crate, with Python's `pow`.
const SIGNATURE: &str = concat!(
    "593b7e017d6d007bb224bd8010f379b4aa719bbad57373be771e80de2ec0826f",
    "a396a4b3e658d9af1efb23b82c4a52e2f5934bc03e67921282c0036e2cc49903",
    "ac0a56262df452b7266ab4cc0694ce8e524e585834f5f1347e3a175b5a40e71a",
    "fbfb8f35ffb16dc666d4b826a88cfd5a491426deb819ebf880057d50b6254674",
);

/// The encoding over the engine, drawing from a source seeded with `seed`.
fn encoding(seed: u64) -> Pkcs1Encoding<Engine, StdRng> {
    Pkcs1Encoding::new(StdRng::seed_from_u64(seed))
}

fn process<R: CryptoRng>(
    encoding: &mut Pkcs1Encoding<Engine, R>,
    direction: CipherDirection,
    key: &Key,
    input: &[u8],
) -> Result<Vec<u8>, Error> {
    encoding.init(direction, key)?;
    let mut output = vec![0; 128];
    let length = encoding.process_block(input, &mut output)?;
    output.truncate(length);
    Ok(output)
}

fn encrypt<R: CryptoRng>(
    encoding: &mut Pkcs1Encoding<Engine, R>,
    key: &Key,
    message: &[u8],
) -> Vec<u8> {
    process(encoding, CipherDirection::Encrypt, key, message).unwrap()
}

fn decrypt<R: CryptoRng>(
    encoding: &mut Pkcs1Encoding<Engine, R>,
    key: &Key,
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    process(encoding, CipherDirection::Decrypt, key, ciphertext)
}

/// `00 || block_type || fill.. || 00 || message` over the 128 bytes of
/// the modulus.
fn block(block_type: u8, fill: u8, message: &[u8]) -> Vec<u8> {
    let mut block = vec![fill; 128];
    block[0] = 0x00;
    block[1] = block_type;
    let separator = 127 - message.len();
    block[separator] = 0x00;
    block[separator + 1..].copy_from_slice(message);
    block
}

#[test]
fn a_message_encrypted_with_the_public_key_decrypts_with_the_private_key() {
    let mut encoding = encoding(1);
    encoding
        .init(CipherDirection::Encrypt, &key(false))
        .unwrap();
    assert_eq!(
        (encoding.input_block_size(), encoding.output_block_size()),
        (117, 128)
    );
    let ciphertext = encrypt(&mut encoding, &key(false), INPUT);
    assert_eq!(ciphertext.len(), 128);
    encoding.init(CipherDirection::Decrypt, &key(true)).unwrap();
    assert_eq!(
        (encoding.input_block_size(), encoding.output_block_size()),
        (128, 117)
    );
    assert_eq!(
        decrypt(&mut encoding, &key(true), &ciphertext).unwrap(),
        INPUT
    );
}

#[test]
fn signing_with_the_private_key_gives_the_signature_worked_out_apart() {
    let mut encoding = encoding(1);
    assert_eq!(encrypt(&mut encoding, &key(true), INPUT), hex(SIGNATURE));
    assert_eq!(
        decrypt(&mut encoding, &key(false), &hex(SIGNATURE)).unwrap(),
        INPUT
    );
}

/// A source that draws every other byte as zero, so that the padding has
/// to draw again.
struct ZeroHeavy {
    inner: StdRng,
    zero: bool,
}

impl TryRng for ZeroHeavy {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.inner.fill_bytes(dst);
        for byte in dst {
            if self.zero {
                *byte = 0;
            }
            self.zero = !self.zero;
        }
        Ok(())
    }
}

impl TryCryptoRng for ZeroHeavy {}

#[test]
fn the_padding_with_a_public_key_is_type_two_and_never_zero() {
    let rng = ZeroHeavy {
        inner: StdRng::seed_from_u64(7),
        zero: true,
    };
    let mut encoding = Pkcs1Encoding::<Engine, _>::new(rng);
    let ciphertext = encrypt(&mut encoding, &key(false), INPUT);
    let block = raw(&key(true), &ciphertext);
    let separator = 127 - INPUT.len();
    assert_eq!(&block[..2], [0x00, 0x02]);
    assert!(block[2..separator].iter().all(|&byte| byte != 0));
    assert_eq!(block[separator], 0x00);
    assert_eq!(&block[separator + 1..], INPUT);
}

#[test]
fn each_encryption_with_the_public_key_pads_afresh() {
    let mut encoding = encoding(2);
    let first = encrypt(&mut encoding, &key(false), INPUT);
    let second = encrypt(&mut encoding, &key(false), INPUT);
    assert_ne!(first, second);
    for ciphertext in [first, second] {
        assert_eq!(
            decrypt(&mut encoding, &key(true), &ciphertext).unwrap(),
            INPUT
        );
    }
}

#[test]
fn a_message_longer_than_the_input_block_is_turned_down() {
    let mut encoding = encoding(4);
    for private in [false, true] {
        encoding
            .init(CipherDirection::Encrypt, &key(private))
            .unwrap();
        let mut output = [0; 128];
        assert_eq!(
            encoding.process_block(&[0x5a; 118], &mut output),
            Err(EncodingError::InputTooLarge)
        );
        assert_eq!(encoding.process_block(&[0x5a; 117], &mut output), Ok(128));
    }
}

#[test]
fn an_empty_message_round_trips_either_way() {
    let mut encoding = encoding(5);
    let ciphertext = encrypt(&mut encoding, &key(false), &[]);
    assert_eq!(decrypt(&mut encoding, &key(true), &ciphertext), Ok(vec![]));
    let signature = encrypt(&mut encoding, &key(true), &[]);
    assert_eq!(decrypt(&mut encoding, &key(false), &signature), Ok(vec![]));
}

#[test]
fn a_message_of_the_whole_output_block_round_trips_either_way() {
    let message = [0x5a; 117];
    let mut encoding = encoding(6);
    let ciphertext = encrypt(&mut encoding, &key(false), &message);
    assert_eq!(
        decrypt(&mut encoding, &key(true), &ciphertext).unwrap(),
        message
    );
    let signature = encrypt(&mut encoding, &key(true), &message);
    assert_eq!(
        decrypt(&mut encoding, &key(false), &signature).unwrap(),
        message
    );
}

#[test]
fn blocks_that_are_not_type_one_fail_verification() {
    let mut filling_the_modulus = block(0x01, 0xff, INPUT);
    filling_the_modulus[0] = 0x01;
    let mut no_zero_after_the_padding = block(0x01, 0xff, INPUT);
    no_zero_after_the_padding[127 - INPUT.len()] = 0xff;
    let mut no_message = vec![0xff; 128];
    no_message[..2].copy_from_slice(&[0x00, 0x01]);
    let mut shifted = vec![0x00];
    shifted.extend(&block(0x01, 0xff, INPUT)[..127]);
    let mut stray_pad_byte = block(0x01, 0xff, INPUT);
    stray_pad_byte[40] = 0xfe;
    let short_padding = block(0x01, 0xff, &[0x5a; 118]);
    let mut encoding = encoding(7);
    for (name, bad) in [
        ("filling the modulus", filling_the_modulus),
        ("of another type", block(0x0f, 0xff, INPUT)),
        ("of type two", block(0x02, 0x17, INPUT)),
        ("with no zero after the padding", no_zero_after_the_padding),
        ("with no message", no_message),
        ("shifted by a byte", shifted),
        ("with a pad byte not ff", stray_pad_byte),
        ("with seven bytes of padding", short_padding),
    ] {
        let signature = raw(&key(true), &bad);
        assert_eq!(
            decrypt(&mut encoding, &key(false), &signature),
            Err(EncodingError::InvalidBlock),
            "{name}"
        );
    }
    let eight_bytes_of_padding = raw(&key(true), &block(0x01, 0xff, &[0x5a; 117]));
    assert_eq!(
        decrypt(&mut encoding, &key(false), &eight_bytes_of_padding),
        Ok(vec![0x5a; 117])
    );
}

#[test]
fn blocks_that_are_not_type_two_fail_decryption() {
    let mut filling_the_modulus = block(0x02, 0x17, INPUT);
    filling_the_modulus[0] = 0x01;
    let mut no_zero = vec![0x17; 128];
    no_zero[..2].copy_from_slice(&[0x00, 0x02]);
    let mut encoding = encoding(8);
    for (name, bad) in [
        ("filling the modulus", filling_the_modulus),
        ("of type one", block(0x01, 0xff, INPUT)),
        ("with no zero", no_zero),
        (
            "with seven bytes of padding",
            block(0x02, 0x17, &[0x5a; 118]),
        ),
    ] {
        let ciphertext = raw(&key(false), &bad);
        assert_eq!(
            decrypt(&mut encoding, &key(true), &ciphertext),
            Err(EncodingError::InvalidBlock),
            "{name}"
        );
    }
    let eight_bytes_of_padding = raw(&key(false), &block(0x02, 0x17, &[0x5a; 117]));
    assert_eq!(
        decrypt(&mut encoding, &key(true), &eight_bytes_of_padding),
        Ok(vec![0x5a; 117])
    );
}

#[test]
fn a_fixed_plaintext_length_gives_the_message_of_a_good_block() {
    let ciphertext = encrypt(&mut encoding(9), &key(false), INPUT);
    let mut encoding = encoding(9).with_plaintext_length(INPUT.len());
    assert_eq!(
        decrypt(&mut encoding, &key(true), &ciphertext).unwrap(),
        INPUT
    );
}

#[test]
fn a_fixed_plaintext_length_gives_drawn_bytes_in_place_of_a_bad_block() {
    let drawn = |length: usize| {
        let mut bytes = vec![0; length];
        StdRng::seed_from_u64(10).fill_bytes(&mut bytes);
        bytes
    };
    let ciphertext = encrypt(&mut encoding(9), &key(false), INPUT);
    // The length of Bouncy Castle's test, twice that of the message.
    let encoding_of = |length| encoding(10).with_plaintext_length(length);
    assert_eq!(
        decrypt(&mut encoding_of(2 * INPUT.len()), &key(true), &ciphertext),
        Ok(drawn(2 * INPUT.len()))
    );
    let type_one = raw(&key(false), &block(0x01, 0xff, INPUT));
    assert_eq!(
        decrypt(&mut encoding_of(INPUT.len()), &key(true), &type_one),
        Ok(drawn(INPUT.len()))
    );
}

#[test]
fn a_fixed_plaintext_length_is_only_checked_where_it_is_used() {
    let mut fitting = encoding(11).with_plaintext_length(117);
    assert_eq!(fitting.init(CipherDirection::Decrypt, &key(true)), Ok(()));
    let mut encoding = encoding(11).with_plaintext_length(118);
    assert_eq!(encoding.init(CipherDirection::Encrypt, &key(false)), Ok(()));
    assert_eq!(encoding.init(CipherDirection::Decrypt, &key(false)), Ok(()));
    let signature = encrypt(&mut encoding, &key(true), INPUT);
    assert_eq!(
        decrypt(&mut encoding, &key(false), &signature).unwrap(),
        INPUT
    );
    assert_eq!(
        encoding.init(CipherDirection::Decrypt, &key(true)),
        Err(EncodingError::InvalidPlaintextLength)
    );
    // A failed init leaves the encoding uninitialized.
    assert_eq!(
        encoding.process_block(&signature, &mut [0; 128]),
        Err(EncodingError::NotInitialized)
    );
}

#[test]
fn an_encoding_not_yet_initialized_processes_nothing() {
    let mut encoding = encoding(12);
    assert_eq!(
        (encoding.input_block_size(), encoding.output_block_size()),
        (0, 0)
    );
    assert_eq!(
        encoding.process_block(INPUT, &mut [0; 128]),
        Err(EncodingError::NotInitialized)
    );
}

#[test]
fn an_output_shorter_than_the_output_block_is_turned_down() {
    let mut encoding = encoding(13);
    encoding
        .init(CipherDirection::Encrypt, &key(false))
        .unwrap();
    assert_eq!(
        encoding.process_block(INPUT, &mut [0; 127]),
        Err(EncodingError::OutputTooShort)
    );
    let ciphertext = encrypt(&mut encoding, &key(false), INPUT);
    encoding.init(CipherDirection::Decrypt, &key(true)).unwrap();
    assert_eq!(
        encoding.process_block(&ciphertext, &mut [0; 116]),
        Err(EncodingError::OutputTooShort)
    );
    assert_eq!(encoding.process_block(&ciphertext, &mut [0; 117]), Ok(32));
}

#[test]
fn the_errors_of_the_engine_come_through() {
    let mut encoding = encoding(14);
    encoding.init(CipherDirection::Decrypt, &key(true)).unwrap();
    assert_eq!(
        encoding.process_block(&[0xff; 128], &mut [0; 117]),
        Err(EncodingError::Cipher(RsaError::InputTooLarge))
    );
}

#[test]
fn the_encoding_is_named_after_its_engine() {
    assert_eq!(encoding(17).to_string(), "RSA/PKCS1Padding");
}

#[test]
fn the_engine_and_the_source_come_back_out_of_the_encoding() {
    let mut rng = StdRng::seed_from_u64(18);
    let mut encoding = Pkcs1Encoding::<Engine, _>::new(&mut rng);
    encoding
        .init(CipherDirection::Encrypt, &key(false))
        .unwrap();
    assert_eq!(encoding.underlying_cipher().input_block_size(), 127);
    let (engine, _) = encoding.into_parts();
    assert_eq!(engine.output_block_size(), 128);
    // The borrow ends with the encoding, and the source is the caller's again.
    let _: &mut StdRng = &mut rng;
}
