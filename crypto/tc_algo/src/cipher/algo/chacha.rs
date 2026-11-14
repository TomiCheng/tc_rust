use tc_asn1::Asn1Oid;
use tc_block_cipher::KeyParams;
use tc_block_modes::IvParams;
use tc_buffered_cipher::{BufferedCipher, BufferedCipherInit, BufferedError, BufferedStreamCipher};
use tc_chacha::ChaCha7539Engine;
use tc_stream_cipher::{KeyWithIvRef, StreamError};

use crate::cipher::{Cipher, CipherDirection, CipherEntry};
use crate::params::KeyWithIvOwned;
use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind, Params};

// The row of ChaCha20 (RFC 8439), to give to DefaultAlgoBuilder::reg_cipher. Its name and alias are
// those of Bouncy Castle's CipherUtilities
pub(super) fn chacha(_context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![Box::new(Row {
        aliases: vec!["CHACHA20".to_string()],
    })]
}

struct Row {
    aliases: Vec<String>,
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        "CHACHA7539"
    }

    fn aliases(&self) -> &[String] {
        &self.aliases
    }

    fn oids(&self) -> &[Asn1Oid] {
        &[]
    }
}

impl CipherEntry for Row {
    fn create(&self) -> Box<dyn Cipher> {
        Box::new(ChaCha7539(BufferedStreamCipher::new(
            ChaCha7539Engine::new(),
        )))
    }
}

// Its params are a KeyWithIvOwned, the same as for the block modes with an IV
struct ChaCha7539(BufferedStreamCipher<ChaCha7539Engine>);

impl BufferedCipher for ChaCha7539 {
    type Error = AlgoError;

    fn block_size(&self) -> usize {
        self.0.block_size()
    }

    fn update_output_len(&self, input_len: usize) -> Result<usize, AlgoError> {
        self.0.update_output_len(input_len).map_err(algo_error)
    }

    fn output_len(&self, input_len: usize) -> Result<usize, AlgoError> {
        self.0.output_len(input_len).map_err(algo_error)
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, AlgoError> {
        self.0.process_bytes(input, output).map_err(algo_error)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        self.0.do_final(output).map_err(algo_error)
    }

    fn reset(&mut self) {
        self.0.reset();
    }
}

impl Cipher for ChaCha7539 {
    fn init(&mut self, direction: CipherDirection, params: &dyn Params) -> Result<(), AlgoError> {
        let params = params
            .as_any()
            .downcast_ref::<KeyWithIvOwned>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        self.0
            .init(direction, &KeyWithIvRef::new(params.key(), params.iv()))
            .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))
    }
}

fn algo_error(error: BufferedError<StreamError>) -> AlgoError {
    let kind = match error {
        BufferedError::NotInitialized => ErrorKind::NotInitialized,
        _ => ErrorKind::DataLength,
    };
    AlgoError::with_source(kind, error)
}

#[cfg(test)]
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
