use tc_buffered_cipher::BufferedCipher;

use crate::{AlgoError, Params};

pub use tc_buffered_cipher::CipherDirection;

// A BufferedCipher of tc_buffered_cipher, with AlgoError for its errors, and with an init taking
// any params, so that every row fits behind Box<dyn Cipher> and still goes wherever a
// BufferedCipher does
pub trait Cipher: BufferedCipher<Error = AlgoError> {
    // Keys the cipher for a message. Params of another type than the row takes are InvalidParams
    fn init(&mut self, direction: CipherDirection, params: &dyn Params) -> Result<(), AlgoError>;

    // process_bytes with an output of its own
    fn update(&mut self, input: &[u8]) -> Result<Vec<u8>, AlgoError> {
        let mut output = vec![0; self.update_output_len(input.len())?];
        let written = self.process_bytes(input, &mut output)?;
        output.truncate(written);
        Ok(output)
    }

    // do_final with an output of its own
    fn finalize(&mut self) -> Result<Vec<u8>, AlgoError> {
        let mut output = vec![0; self.output_len(0)?];
        let written = self.do_final(&mut output)?;
        output.truncate(written);
        Ok(output)
    }
}

#[cfg(all(test, feature = "aes"))]
mod tests {
    use tc_buffered_cipher::BufferedCipher;

    use super::CipherDirection;
    use crate::params::KeyWithIvOwned;
    use crate::{AlgoBuilder, DefaultAlgoBuilder};

    // Code written for any BufferedCipher, knowing nothing of tc_algo
    fn encrypt_all<C: BufferedCipher + ?Sized>(cipher: &mut C, input: &[u8]) -> Vec<u8>
    where
        C::Error: core::fmt::Debug,
    {
        let mut output = vec![0; cipher.output_len(input.len()).unwrap()];
        let mut written = cipher.process_bytes(input, &mut output).unwrap();
        written += cipher.do_final(&mut output[written..]).unwrap();
        output.truncate(written);
        output
    }

    #[test]
    fn a_cipher_from_the_factory_goes_where_a_buffered_cipher_does() {
        let algo = DefaultAlgoBuilder::default().build();
        let name = "AES/CBC/PKCS7PADDING";
        let params = KeyWithIvOwned::new(vec![7; 16], vec![9; 16]);
        let message = b"attack at dawn";

        let mut cipher = algo.cipher().get_by_name(name).unwrap();
        cipher.init(CipherDirection::Encrypt, &params).unwrap();
        let output = encrypt_all(cipher.as_mut(), message);

        let expected = algo
            .cipher()
            .encrypt_by_name(name, &params, message)
            .unwrap();
        assert_eq!(output, expected);
    }
}
