use core::error::Error;

use tc_aes::AesEngine;
use tc_asn1::Asn1Oid;
use tc_block_modes::{CbcBlockCipher, EcbBlockCipher, KeyWithIvRef};
use tc_buffered_cipher::{
    BufferedBlockCipher, BufferedCipher, BufferedCipherInit, BufferedError,
    CipherDirection as BufferedDirection, PaddedBufferedBlockCipher,
};

use crate::cipher::{BlockCipherParams, Cipher, CipherDirection, CipherEntry};
use crate::{AlgoError, EntryBase, ErrorKind, Params};

// The rows of AES, to give to DefaultAlgoBuilder::reg_cipher. Their names and OIDs are those of
// Bouncy Castle's CipherUtilities, where the NIST ECB and CBC OIDs mean those modes with PKCS#7
pub(super) fn aes() -> Vec<Box<dyn CipherEntry>> {
    vec![
        row("AES/ECB/NOPADDING", &[], &[], || {
            Box::new(Buffered(BufferedBlockCipher::new(ecb())))
        }),
        row(
            "AES/ECB/PKCS7PADDING",
            &["AES/ECB/PKCS7", "AES/ECB/PKCS5PADDING", "AES/ECB/PKCS5"],
            &[
                "2.16.840.1.101.3.4.1.1",
                "2.16.840.1.101.3.4.1.21",
                "2.16.840.1.101.3.4.1.41",
            ],
            || Box::new(Buffered(PaddedBufferedBlockCipher::new(ecb()))),
        ),
        row("AES/CBC/NOPADDING", &[], &[], || {
            Box::new(Buffered(BufferedBlockCipher::new(cbc())))
        }),
        row(
            "AES/CBC/PKCS7PADDING",
            &["AES/CBC/PKCS7", "AES/CBC/PKCS5PADDING", "AES/CBC/PKCS5"],
            &[
                "2.16.840.1.101.3.4.1.2",
                "2.16.840.1.101.3.4.1.22",
                "2.16.840.1.101.3.4.1.42",
            ],
            || Box::new(Buffered(PaddedBufferedBlockCipher::new(cbc()))),
        ),
    ]
}

fn ecb() -> EcbBlockCipher<AesEngine> {
    EcbBlockCipher::new(AesEngine::new())
}

fn cbc() -> CbcBlockCipher<AesEngine> {
    CbcBlockCipher::new(AesEngine::new())
}

fn row(
    name: &'static str,
    aliases: &[&str],
    oids: &[&str],
    create: fn() -> Box<dyn Cipher>,
) -> Box<dyn CipherEntry> {
    Box::new(Row {
        name,
        aliases: aliases.iter().map(|alias| alias.to_string()).collect(),
        oids: oids.iter().map(|dotted| oid(dotted)).collect(),
        create,
    })
}

fn oid(dotted: &str) -> Asn1Oid {
    dotted.parse().expect("a valid OID")
}

struct Row {
    name: &'static str,
    aliases: Vec<String>,
    oids: Vec<Asn1Oid>,
    create: fn() -> Box<dyn Cipher>,
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        self.name
    }

    fn aliases(&self) -> &[String] {
        &self.aliases
    }

    fn oids(&self) -> &[Asn1Oid] {
        &self.oids
    }
}

impl CipherEntry for Row {
    fn create(&self) -> Box<dyn Cipher> {
        (self.create)()
    }
}

// Puts a buffered cipher, whatever its mode and padding, behind Cipher. Its params are those of
// BlockCipherParams
struct Buffered<C>(C);

impl<C, E, I> Cipher for Buffered<C>
where
    C: BufferedCipher<Error = BufferedError<E>>
        + for<'a> BufferedCipherInit<KeyWithIvRef<'a>, Error = I>,
    E: Error + Send + Sync + 'static,
    I: Error + Send + Sync + 'static,
{
    fn init(&mut self, direction: CipherDirection, params: &dyn Params) -> Result<(), AlgoError> {
        let params = BlockCipherParams::from_bytes(params.as_bytes())?;
        // As in Bouncy Castle, no IV means all zeros; ECB does not read it
        let iv = params.iv().unwrap_or(&[0; 16]);
        let direction = match direction {
            CipherDirection::Encrypt => BufferedDirection::Encrypt,
            CipherDirection::Decrypt => BufferedDirection::Decrypt,
        };
        self.0
            .init(direction, &KeyWithIvRef::new(params.key(), iv))
            .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))
    }

    fn update(&mut self, input: &[u8]) -> Result<Vec<u8>, AlgoError> {
        let len = self.0.update_output_len(input.len()).map_err(algo_error)?;
        let mut output = vec![0; len];
        let written = self
            .0
            .process_bytes(input, &mut output)
            .map_err(algo_error)?;
        output.truncate(written);
        Ok(output)
    }

    fn finalize(&mut self) -> Result<Vec<u8>, AlgoError> {
        let len = self.0.output_len(0).map_err(algo_error)?;
        let mut output = vec![0; len];
        let written = self.0.do_final(&mut output).map_err(algo_error)?;
        output.truncate(written);
        Ok(output)
    }
}

fn algo_error<E: Error + Send + Sync + 'static>(error: BufferedError<E>) -> AlgoError {
    let kind = match error {
        BufferedError::NotInitialized => ErrorKind::NotInitialized,
        BufferedError::CorruptPadding => ErrorKind::InvalidCiphertext,
        _ => ErrorKind::DataLength,
    };
    AlgoError::with_source(kind, error)
}

#[cfg(test)]
mod tests {
    use super::aes;
    use crate::cipher::{BlockCipherParams, Cipher, CipherDirection, CipherEntry};
    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind, Params};

    // The example in FIPS 197, appendix C.1
    const KEY: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const PLAINTEXT: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    const CIPHERTEXT: [u8; 16] = [
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5,
        0x5a,
    ];

    // The first block of the example in NIST SP 800-38A, F.2.1
    const CBC_KEY: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    const CBC_IV: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const CBC_PLAINTEXT: [u8; 16] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a,
    ];
    const CBC_CIPHERTEXT: [u8; 16] = [
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19,
        0x7d,
    ];

    fn entry(name: &str) -> Box<dyn CipherEntry> {
        aes()
            .into_iter()
            .find(|row| row.name() == name)
            .expect("a row of AES")
    }

    fn keyed(direction: CipherDirection) -> Box<dyn Cipher> {
        let mut cipher = entry("AES/ECB/NOPADDING").create();
        let params = BlockCipherParams::new().with_key(&KEY);
        cipher.init(direction, &params).unwrap();
        cipher
    }

    fn init_error(name: &str, params: &dyn Params) -> ErrorKind {
        let mut cipher = entry(name).create();
        let result = cipher.init(CipherDirection::Encrypt, params);
        result.unwrap_err().kind()
    }

    #[test]
    fn the_row_has_no_aliases_or_oids() {
        let entry = entry("AES/ECB/NOPADDING");
        assert!(entry.aliases().is_empty());
        assert!(entry.oids().is_empty());
    }

    #[test]
    fn the_cbc_row_gives_the_standard_ciphertext_through_the_helpers() {
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();
        let params = BlockCipherParams::new().with_key(&CBC_KEY).with_iv(&CBC_IV);

        let encrypted = ciphers
            .encrypt_by_name("AES/CBC/NOPADDING", &params, &CBC_PLAINTEXT)
            .unwrap();
        assert_eq!(encrypted, CBC_CIPHERTEXT);

        let decrypted = ciphers
            .decrypt_by_name("AES/CBC/NOPADDING", &params, &CBC_CIPHERTEXT)
            .unwrap();
        assert_eq!(decrypted, CBC_PLAINTEXT);
    }

    #[test]
    fn the_padded_rows_take_back_what_they_encrypted() {
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();
        let message = b"attack at dawn";

        let without_iv = BlockCipherParams::new().with_key(&KEY);
        let with_iv = BlockCipherParams::new().with_key(&KEY).with_iv(&CBC_IV);
        let rows: [(&str, &dyn Params); 2] = [
            ("AES/ECB/PKCS7PADDING", &without_iv),
            ("AES/CBC/PKCS7PADDING", &with_iv),
        ];

        for (name, params) in rows {
            let encrypted = ciphers.encrypt_by_name(name, params, message).unwrap();
            assert_eq!(encrypted.len(), 16);
            let decrypted = ciphers.decrypt_by_name(name, params, &encrypted).unwrap();
            assert_eq!(decrypted, message);
        }
    }

    #[test]
    fn a_padded_row_reports_a_bad_padding_as_invalid_ciphertext() {
        let algo = DefaultAlgoBuilder::default().build();
        let params = BlockCipherParams::new().with_key(&KEY);

        // PLAINTEXT ends in 0xff, which is no PKCS#7 padding
        let result = algo
            .cipher()
            .decrypt_by_name("AES/ECB/PKCS7PADDING", &params, &CIPHERTEXT);
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidCiphertext);
    }

    #[test]
    fn ecb_does_not_read_an_iv() {
        let algo = DefaultAlgoBuilder::default().build();
        let params = BlockCipherParams::new().with_key(&KEY).with_iv(&CBC_IV);

        let encrypted = algo
            .cipher()
            .encrypt_by_name("AES/ECB/NOPADDING", &params, &PLAINTEXT)
            .unwrap();
        assert_eq!(encrypted, CIPHERTEXT);
    }

    // With an IV of zeros, the first block of CBC is the same as ECB
    #[test]
    fn cbc_without_an_iv_uses_zeros() {
        let algo = DefaultAlgoBuilder::default().build();
        let params = BlockCipherParams::new().with_key(&KEY);

        let encrypted = algo
            .cipher()
            .encrypt_by_name("AES/CBC/NOPADDING", &params, &PLAINTEXT)
            .unwrap();
        assert_eq!(encrypted, CIPHERTEXT);
    }

    #[test]
    fn init_refuses_a_key_or_an_iv_of_the_wrong_length() {
        let short_key = BlockCipherParams::new().with_key(&KEY[..15]);
        assert_eq!(
            init_error("AES/ECB/NOPADDING", &short_key),
            ErrorKind::InvalidParams
        );

        let short_iv = BlockCipherParams::new()
            .with_key(&KEY)
            .with_iv(&CBC_IV[..15]);
        assert_eq!(
            init_error("AES/CBC/NOPADDING", &short_iv),
            ErrorKind::InvalidParams
        );
    }

    struct RawKey;

    impl Params for RawKey {
        fn as_bytes(&self) -> &[u8] {
            &KEY
        }
    }

    #[test]
    fn init_refuses_params_in_another_format() {
        assert_eq!(
            init_error("AES/ECB/NOPADDING", &RawKey),
            ErrorKind::InvalidParams
        );
    }

    #[test]
    fn a_new_builder_finds_the_row_by_its_name_whatever_the_case() {
        let algo = DefaultAlgoBuilder::default().build();
        assert!(algo.cipher().get_by_name("AES/ECB/NoPadding").is_some());
        assert!(algo.cipher().get_by_name("aes/ecb/nopadding").is_some());
    }

    #[test]
    fn update_holds_a_partial_block_and_gives_the_standard_ciphertext_once_it_is_complete() {
        let mut cipher = keyed(CipherDirection::Encrypt);
        assert!(cipher.update(&PLAINTEXT[..5]).unwrap().is_empty());
        assert_eq!(cipher.update(&PLAINTEXT[5..]).unwrap(), CIPHERTEXT);
        assert!(cipher.finalize().unwrap().is_empty());
    }

    #[test]
    fn decrypting_the_standard_ciphertext_gives_the_plaintext() {
        let mut cipher = keyed(CipherDirection::Decrypt);
        assert_eq!(cipher.update(&CIPHERTEXT).unwrap(), PLAINTEXT);
        assert!(cipher.finalize().unwrap().is_empty());
    }

    #[test]
    fn finalize_reports_a_partial_last_block() {
        let mut cipher = keyed(CipherDirection::Encrypt);
        cipher.update(&PLAINTEXT[..5]).unwrap();
        let error = cipher.finalize().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DataLength);
    }

    #[test]
    fn update_and_finalize_report_a_cipher_that_was_not_initialized() {
        let mut cipher = entry("AES/ECB/NOPADDING").create();
        let error = cipher.update(&PLAINTEXT).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
        let error = cipher.finalize().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
    }
}
