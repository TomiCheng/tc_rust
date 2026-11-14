use tc_buffered_cipher::BufferedStreamCipher;
#[cfg(feature = "xchacha20")]
use tc_chacha::XChaCha20Engine;
#[cfg(feature = "chacha")]
use tc_chacha::{ChaCha7539Engine, ChaChaEngine};

use super::stream::{Nonced, stream_row};
use crate::DefaultAlgoContext;
use crate::cipher::CipherEntry;

// The rows of ChaCha20, to give to DefaultAlgoBuilder::reg_cipher. Their names and alias are those
// of Bouncy Castle's CipherUtilities: CHACHA7539 is that of RFC 8439, with a nonce of 12 bytes;
// CHACHA the original, with a nonce of 8
#[cfg(feature = "chacha")]
pub(super) fn chacha(_context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![
        stream_row(&["CHACHA7539", "CHACHA20"], &[], || {
            Box::new(Nonced(BufferedStreamCipher::new(ChaCha7539Engine::new())))
        }),
        stream_row(&["CHACHA"], &[], || {
            Box::new(Nonced(BufferedStreamCipher::new(ChaChaEngine::new())))
        }),
    ]
}

// XChaCha20, ChaCha20 with a nonce of 24 bytes
#[cfg(feature = "xchacha20")]
pub(super) fn xchacha20(_context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![stream_row(&["XCHACHA20"], &[], || {
        Box::new(Nonced(BufferedStreamCipher::new(XChaCha20Engine::new())))
    })]
}

#[cfg(all(test, feature = "chacha"))]
mod tests {
    use super::chacha;
    use crate::cipher::{Cipher, CipherDirection, CipherEntry};
    use crate::params::{KeyOwned, KeyWithIvOwned};
    use crate::{AlgoBuilder, DefaultAlgoBuilder, DefaultAlgoContext, ErrorKind};

    const NAME: &str = "CHACHA7539";

    fn entry() -> Box<dyn CipherEntry> {
        chacha(&DefaultAlgoContext::for_tests())
            .into_iter()
            .next()
            .expect("the row of ChaCha20")
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    // The encryption example in RFC 8439, section 2.4.2
    fn params() -> KeyWithIvOwned {
        KeyWithIvOwned::new(
            hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            hex("000000000000004a00000000"),
        )
    }

    const PLAINTEXT: &[u8] =
        b"Ladies and Gentlemen of the class of '99: If I could offer you only \
                               one tip for the future, sunscreen would be it.";

    fn ciphertext() -> Vec<u8> {
        hex(concat!(
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b",
            "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8",
            "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736",
            "5af90bbf74a35be6b40b8eedf2785e42874d",
        ))
    }

    // The example starts at block one, whereas the row starts at block zero
    fn from_block_one(text: &[u8]) -> Vec<u8> {
        [&[0; 64], text].concat()
    }

    #[test]
    fn the_row_gives_the_standard_ciphertext_through_the_helpers() {
        let algo = DefaultAlgoBuilder::default().build();
        let sealed = algo
            .cipher()
            .encrypt_by_name(NAME, &params(), &from_block_one(PLAINTEXT))
            .unwrap();
        assert_eq!(sealed[64..], ciphertext());

        let opened = algo
            .cipher()
            .decrypt_by_name(NAME, &params(), &from_block_one(&ciphertext()))
            .unwrap();
        assert_eq!(opened[64..], *PLAINTEXT);
    }

    #[test]
    fn the_row_is_found_by_its_alias_whatever_the_case() {
        let algo = DefaultAlgoBuilder::default().build();
        assert!(algo.cipher().get_by_name("CHACHA20").is_ok());
        assert!(algo.cipher().get_by_name("chacha7539").is_ok());
    }

    #[test]
    fn a_message_in_pieces_gives_the_same_ciphertext_with_nothing_left_for_finalize() {
        let message = from_block_one(PLAINTEXT);
        let mut cipher = entry().create();
        cipher.init(CipherDirection::Encrypt, &params()).unwrap();
        let mut sealed = cipher.update(&message[..70]).unwrap();
        sealed.extend(cipher.update(&message[70..]).unwrap());
        assert!(cipher.finalize().unwrap().is_empty());
        assert_eq!(sealed[64..], ciphertext());
    }

    fn init_error(cipher: &mut Box<dyn Cipher>, params: &dyn crate::Params) -> ErrorKind {
        let result = cipher.init(CipherDirection::Encrypt, params);
        result.unwrap_err().kind()
    }

    #[test]
    fn init_refuses_a_wrong_key_a_wrong_nonce_or_params_of_another_type() {
        let mut cipher = entry().create();
        let short_key = KeyWithIvOwned::new(vec![0; 16], vec![0; 12]);
        assert_eq!(
            init_error(&mut cipher, &short_key),
            ErrorKind::InvalidParams
        );
        let short_nonce = KeyWithIvOwned::new(vec![0; 32], vec![0; 8]);
        assert_eq!(
            init_error(&mut cipher, &short_nonce),
            ErrorKind::InvalidParams
        );
        let no_nonce = KeyOwned::new(vec![0; 32]);
        assert_eq!(init_error(&mut cipher, &no_nonce), ErrorKind::InvalidParams);
    }

    #[test]
    fn a_failed_init_leaves_the_cipher_not_initialized() {
        let mut cipher = entry().create();
        cipher.init(CipherDirection::Encrypt, &params()).unwrap();
        let short_key = KeyWithIvOwned::new(vec![0; 16], vec![0; 12]);
        init_error(&mut cipher, &short_key);
        let error = cipher.update(PLAINTEXT).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
    }

    #[test]
    fn update_and_finalize_report_a_cipher_that_was_not_initialized() {
        let mut cipher = entry().create();
        let error = cipher.update(PLAINTEXT).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
        let error = cipher.finalize().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
    }

    #[test]
    fn the_buffer_calls_write_as_much_as_they_read_with_a_block_size_of_zero() {
        let message = from_block_one(PLAINTEXT);
        let mut cipher = entry().create();
        cipher.init(CipherDirection::Encrypt, &params()).unwrap();
        assert_eq!(cipher.block_size(), 0);
        assert_eq!(cipher.output_len(0).unwrap(), 0);

        let mut sealed = vec![0; cipher.output_len(message.len()).unwrap()];
        let mut written = cipher.process_byte(message[0], &mut sealed).unwrap();
        written += cipher
            .process_bytes(&message[1..], &mut sealed[written..])
            .unwrap();
        written += cipher.do_final(&mut sealed[written..]).unwrap();
        assert_eq!(written, message.len());
        assert_eq!(sealed[64..], ciphertext());
    }

    #[test]
    fn an_output_shorter_than_the_input_is_reported_as_data_length() {
        let mut cipher = entry().create();
        cipher.init(CipherDirection::Encrypt, &params()).unwrap();
        let error = cipher.process_bytes(PLAINTEXT, &mut [0; 8]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DataLength);
    }

    #[test]
    fn reset_starts_the_keystream_over() {
        let mut cipher = entry().create();
        cipher.init(CipherDirection::Encrypt, &params()).unwrap();
        let first = cipher.update(PLAINTEXT).unwrap();
        cipher.reset();
        assert_eq!(cipher.update(PLAINTEXT).unwrap(), first);
    }

    #[test]
    fn finalize_restarts_the_keystream_as_in_bouncy_castle() {
        let mut cipher = entry().create();
        cipher.init(CipherDirection::Encrypt, &params()).unwrap();
        let first = cipher.update(PLAINTEXT).unwrap();
        cipher.finalize().unwrap();
        assert_eq!(cipher.update(PLAINTEXT).unwrap(), first);
    }
}

#[cfg(all(test, any(feature = "chacha", feature = "xchacha20")))]
mod variant_tests {
    #![allow(unused_imports)]
    use tc_stream_cipher::{CipherDirection, KeyRef, KeyWithIvRef, StreamCipher, StreamCipherInit};

    use crate::params::{KeyOwned, KeyWithIvOwned};
    use crate::{AlgoBuilder, DefaultAlgoBuilder};

    #[allow(dead_code)]
    const MESSAGE: &[u8] = b"attack at dawn, then retreat at dusk";

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    // RFC 8439, appendix A.1, test vector 1: the zero key and nonce, block 0, which the original
    // ChaCha with its 8-byte nonce gives too
    #[cfg(feature = "chacha")]
    #[test]
    fn the_original_chacha_gives_the_zero_vector_of_rfc_8439() {
        let algo = DefaultAlgoBuilder::default().build();
        let params = KeyWithIvOwned::new(vec![0; 32], vec![0; 8]);
        let output = algo
            .cipher()
            .encrypt_by_name("CHACHA", &params, &[0; 32])
            .unwrap();
        assert_eq!(
            output,
            unhex("76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7")
        );
    }

    #[cfg(feature = "xchacha20")]
    #[test]
    fn xchacha20_gives_what_its_engine_gives() {
        let key = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let iv = unhex("000102030405060708090a0b0c0d0e0f1011121314151617");
        let _ = &iv;
        let mut engine = tc_chacha::XChaCha20Engine::new();
        engine
            .init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &iv))
            .unwrap();
        let mut expected = vec![0; MESSAGE.len()];
        engine.process_bytes(MESSAGE, &mut expected).unwrap();

        let algo = DefaultAlgoBuilder::default().build();
        let output = algo
            .cipher()
            .encrypt_by_name(
                "XCHACHA20",
                &KeyWithIvOwned::new(key.clone(), iv.clone()),
                MESSAGE,
            )
            .unwrap();
        assert_eq!(output, expected);
        let back = algo
            .cipher()
            .decrypt_by_name(
                "XCHACHA20",
                &KeyWithIvOwned::new(key.clone(), iv.clone()),
                &output,
            )
            .unwrap();
        assert_eq!(back, MESSAGE);
    }
}
