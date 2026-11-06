use core::error::Error;

use tc_aead_cipher::{AeadCipher, AeadCipherInit, AeadError, AeadParamsOwned, GcmBlockCipher};
use tc_aes::AesEngine;
use tc_asn1::Asn1Oid;
use tc_block_cipher::CipherDirection as BlockDirection;
use tc_block_modes::{CbcBlockCipher, CfbBlockCipher, EcbBlockCipher, OfbBlockCipher};
use tc_buffered_cipher::{
    BufferedBlockCipher, BufferedCipher, BufferedCipherInit, BufferedError,
    CipherDirection as BufferedDirection, PaddedBufferedBlockCipher,
};

use crate::cipher::{Cipher, CipherDirection, CipherEntry, IvParams, KeyWithIvOwned};
use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind, KeyOwned, Params};

// The rows of AES, to give to DefaultAlgoBuilder::reg_cipher. Their names and OIDs are those of
// Bouncy Castle's CipherUtilities, where the NIST ECB and CBC OIDs mean those modes with PKCS#7
pub(super) fn aes(_context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![
        row("AES/ECB/NOPADDING", &[], &[], || {
            Box::new(Ecb(Buffered(BufferedBlockCipher::new(ecb()))))
        }),
        row(
            "AES/ECB/PKCS7PADDING",
            &["AES/ECB/PKCS7", "AES/ECB/PKCS5PADDING", "AES/ECB/PKCS5"],
            &[
                "2.16.840.1.101.3.4.1.1",
                "2.16.840.1.101.3.4.1.21",
                "2.16.840.1.101.3.4.1.41",
            ],
            || Box::new(Ecb(Buffered(PaddedBufferedBlockCipher::new(ecb())))),
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
        row(
            "AES/CFB/NOPADDING",
            &[],
            &[
                "2.16.840.1.101.3.4.1.4",
                "2.16.840.1.101.3.4.1.24",
                "2.16.840.1.101.3.4.1.44",
            ],
            || Box::new(Buffered(BufferedBlockCipher::new(cfb()))),
        ),
        row(
            "AES/OFB/NOPADDING",
            &[],
            &[
                "2.16.840.1.101.3.4.1.3",
                "2.16.840.1.101.3.4.1.23",
                "2.16.840.1.101.3.4.1.43",
            ],
            || Box::new(Buffered(BufferedBlockCipher::new(ofb()))),
        ),
        row(
            "AES/GCM/NOPADDING",
            &[],
            &[
                "2.16.840.1.101.3.4.1.6",
                "2.16.840.1.101.3.4.1.26",
                "2.16.840.1.101.3.4.1.46",
            ],
            || Box::new(Gcm(GcmBlockCipher::new(AesEngine::new()))),
        ),
    ]
}

fn ecb() -> EcbBlockCipher<AesEngine> {
    EcbBlockCipher::new(AesEngine::new())
}

fn cbc() -> CbcBlockCipher<AesEngine> {
    CbcBlockCipher::new(AesEngine::new())
}

fn cfb() -> CfbBlockCipher<AesEngine> {
    CfbBlockCipher::new(AesEngine::new(), BLOCK_BYTES * 8)
}

fn ofb() -> OfbBlockCipher<AesEngine> {
    OfbBlockCipher::new(AesEngine::new(), BLOCK_BYTES * 8)
}

const BLOCK_BYTES: usize = 16;

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

// Puts a buffered cipher, whatever its padding, behind Cipher. Its params are a KeyWithIvOwned.
// Unlike Bouncy Castle, a short IV is refused: padded with zeros, it could repeat a keystream
// without anyone noticing
struct Buffered<C>(C);

impl<C, E, I> Cipher for Buffered<C>
where
    C: BufferedCipher<Error = BufferedError<E>> + BufferedCipherInit<KeyWithIvOwned, Error = I>,
    E: Error + Send + Sync + 'static,
    I: Error + Send + Sync + 'static,
{
    fn init(&mut self, direction: CipherDirection, params: &dyn Params) -> Result<(), AlgoError> {
        let params = downcast::<KeyWithIvOwned>(params)?;
        if params.iv().len() != BLOCK_BYTES {
            return Err(AlgoError::new(ErrorKind::InvalidParams));
        }
        self.0
            .init(buffered_direction(direction), params)
            .map_err(invalid_params)
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

// ECB has no IV, so its params are a KeyOwned
struct Ecb<C>(Buffered<C>);

impl<C, I> Cipher for Ecb<C>
where
    Buffered<C>: Cipher,
    C: BufferedCipherInit<KeyOwned, Error = I>,
    I: Error + Send + Sync + 'static,
{
    fn init(&mut self, direction: CipherDirection, params: &dyn Params) -> Result<(), AlgoError> {
        let params = downcast::<KeyOwned>(params)?;
        self.0
            .0
            .init(buffered_direction(direction), params)
            .map_err(invalid_params)
    }

    fn update(&mut self, input: &[u8]) -> Result<Vec<u8>, AlgoError> {
        self.0.update(input)
    }

    fn finalize(&mut self) -> Result<Vec<u8>, AlgoError> {
        self.0.finalize()
    }
}

// Its params are an AeadParamsOwned. Encryption ends with the tag, and decryption expects it at
// the end of the input. As in Bouncy Castle, update may give plaintext before finalize has checked
// the tag, so a caller that uses update has to discard it when finalize fails
struct Gcm(GcmBlockCipher<AesEngine>);

impl Cipher for Gcm {
    fn init(&mut self, direction: CipherDirection, params: &dyn Params) -> Result<(), AlgoError> {
        let params = downcast::<AeadParamsOwned>(params)?;
        self.0
            .init(block_direction(direction), params)
            .map_err(invalid_params)
    }

    fn update(&mut self, input: &[u8]) -> Result<Vec<u8>, AlgoError> {
        let len = self.0.update_output_len(input.len()).map_err(aead_error)?;
        let mut output = vec![0; len];
        let written = self
            .0
            .process_bytes(input, &mut output)
            .map_err(aead_error)?;
        output.truncate(written);
        Ok(output)
    }

    fn finalize(&mut self) -> Result<Vec<u8>, AlgoError> {
        let len = self.0.output_len(0).map_err(aead_error)?;
        let mut output = vec![0; len];
        let written = self.0.do_final(&mut output).map_err(aead_error)?;
        output.truncate(written);
        Ok(output)
    }
}

fn downcast<T: 'static>(params: &dyn Params) -> Result<&T, AlgoError> {
    params
        .as_any()
        .downcast_ref::<T>()
        .ok_or(AlgoError::new(ErrorKind::InvalidParams))
}

fn buffered_direction(direction: CipherDirection) -> BufferedDirection {
    match direction {
        CipherDirection::Encrypt => BufferedDirection::Encrypt,
        CipherDirection::Decrypt => BufferedDirection::Decrypt,
    }
}

fn block_direction(direction: CipherDirection) -> BlockDirection {
    match direction {
        CipherDirection::Encrypt => BlockDirection::Encrypt,
        CipherDirection::Decrypt => BlockDirection::Decrypt,
    }
}

fn invalid_params<E: Error + Send + Sync + 'static>(error: E) -> AlgoError {
    AlgoError::with_source(ErrorKind::InvalidParams, error)
}

fn algo_error<E: Error + Send + Sync + 'static>(error: BufferedError<E>) -> AlgoError {
    let kind = match error {
        BufferedError::NotInitialized => ErrorKind::NotInitialized,
        BufferedError::CorruptPadding => ErrorKind::InvalidCiphertext,
        _ => ErrorKind::DataLength,
    };
    AlgoError::with_source(kind, error)
}

fn aead_error<E: Error + Send + Sync + 'static>(error: AeadError<E>) -> AlgoError {
    let kind = match error {
        // A finished encryption takes a new init, so that no nonce is used twice
        AeadError::NotInitialized | AeadError::AlreadyFinalized => ErrorKind::NotInitialized,
        // Too short to hold the tag is told apart no more than a wrong tag
        AeadError::AuthenticationFailed | AeadError::CiphertextTooShort { .. } => {
            ErrorKind::InvalidCiphertext
        }
        _ => ErrorKind::DataLength,
    };
    AlgoError::with_source(kind, error)
}

#[cfg(test)]
mod tests {
    use super::aes;
    use crate::cipher::{AeadParamsOwned, Cipher, CipherDirection, CipherEntry, KeyWithIvOwned};
    use crate::{AlgoBuilder, DefaultAlgoBuilder, DefaultAlgoContext, ErrorKind, KeyOwned, Params};

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

    // The first two blocks of the examples in NIST SP 800-38A, F.3.13 and F.4.1, with the key and
    // IV above. The two modes agree on the first block only
    const SECOND_PLAINTEXT: [u8; 16] = [
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e,
        0x51,
    ];
    const CFB_CIPHERTEXT: [u8; 32] = [
        0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20, 0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c, 0xfb,
        0x4a, 0xc8, 0xa6, 0x45, 0x37, 0xa0, 0xb3, 0xa9, 0x3f, 0xcd, 0xe3, 0xcd, 0xad, 0x9f, 0x1c,
        0xe5, 0x8b,
    ];
    const OFB_CIPHERTEXT: [u8; 32] = [
        0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20, 0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c, 0xfb,
        0x4a, 0x77, 0x89, 0x50, 0x8d, 0x16, 0x91, 0x8f, 0x03, 0xf5, 0x3c, 0x52, 0xda, 0xc5, 0x4e,
        0xd8, 0x25,
    ];

    fn entry(name: &str) -> Box<dyn CipherEntry> {
        aes(&DefaultAlgoContext::for_tests())
            .into_iter()
            .find(|row| row.name() == name)
            .expect("a row of AES")
    }

    fn key_only(key: &[u8]) -> KeyOwned {
        KeyOwned::new(key.to_vec())
    }

    fn key_and_iv(key: &[u8], iv: &[u8]) -> KeyWithIvOwned {
        KeyWithIvOwned::new(key.to_vec(), iv.to_vec())
    }

    fn keyed(direction: CipherDirection) -> Box<dyn Cipher> {
        let mut cipher = entry("AES/ECB/NOPADDING").create();
        cipher.init(direction, &key_only(&KEY)).unwrap();
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
        let params = key_and_iv(&CBC_KEY, &CBC_IV);

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
    fn the_cfb_and_ofb_rows_give_the_standard_ciphertext() {
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();
        let params = key_and_iv(&CBC_KEY, &CBC_IV);
        let plaintext = [CBC_PLAINTEXT, SECOND_PLAINTEXT].concat();

        for (name, ciphertext) in [
            ("AES/CFB/NOPADDING", CFB_CIPHERTEXT),
            ("AES/OFB/NOPADDING", OFB_CIPHERTEXT),
        ] {
            let encrypted = ciphers.encrypt_by_name(name, &params, &plaintext).unwrap();
            assert_eq!(encrypted, ciphertext);

            let decrypted = ciphers.decrypt_by_name(name, &params, &ciphertext).unwrap();
            assert_eq!(decrypted, plaintext);
        }
    }

    #[test]
    fn the_cfb_and_ofb_rows_take_a_partial_last_block() {
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();
        let params = key_and_iv(&CBC_KEY, &CBC_IV);
        let plaintext = [CBC_PLAINTEXT, SECOND_PLAINTEXT].concat();

        for (name, ciphertext) in [
            ("AES/CFB/NOPADDING", CFB_CIPHERTEXT),
            ("AES/OFB/NOPADDING", OFB_CIPHERTEXT),
        ] {
            let encrypted = ciphers
                .encrypt_by_name(name, &params, &plaintext[..20])
                .unwrap();
            assert_eq!(encrypted, ciphertext[..20]);
        }
    }

    #[test]
    fn finalize_goes_back_to_the_iv_as_in_bouncy_castle() {
        let params = key_and_iv(&CBC_KEY, &CBC_IV);

        for name in [
            "AES/CBC/NOPADDING",
            "AES/CFB/NOPADDING",
            "AES/OFB/NOPADDING",
        ] {
            let mut cipher = entry(name).create();
            cipher.init(CipherDirection::Encrypt, &params).unwrap();
            let first = cipher.update(&CBC_PLAINTEXT).unwrap();
            cipher.finalize().unwrap();
            assert_eq!(cipher.update(&CBC_PLAINTEXT).unwrap(), first);
        }
    }

    #[test]
    fn the_padded_rows_take_back_what_they_encrypted() {
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();
        let message = b"attack at dawn";

        let without_iv = key_only(&KEY);
        let with_iv = key_and_iv(&KEY, &CBC_IV);
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
        let params = key_only(&KEY);

        // PLAINTEXT ends in 0xff, which is no PKCS#7 padding
        let result = algo
            .cipher()
            .decrypt_by_name("AES/ECB/PKCS7PADDING", &params, &CIPHERTEXT);
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidCiphertext);
    }

    #[test]
    fn the_ecb_rows_refuse_params_with_an_iv() {
        let params = key_and_iv(&KEY, &CBC_IV);
        for name in ["AES/ECB/NOPADDING", "AES/ECB/PKCS7PADDING"] {
            assert_eq!(init_error(name, &params), ErrorKind::InvalidParams);
        }
    }

    // With an IV of zeros, the first block of CBC is the same as ECB
    #[test]
    fn an_iv_of_zeros_works_when_it_is_given() {
        let algo = DefaultAlgoBuilder::default().build();
        let params = key_and_iv(&KEY, &[0; 16]);

        let encrypted = algo
            .cipher()
            .encrypt_by_name("AES/CBC/NOPADDING", &params, &PLAINTEXT)
            .unwrap();
        assert_eq!(encrypted, CIPHERTEXT);
    }

    #[test]
    fn the_modes_with_an_iv_refuse_a_missing_or_a_wrong_one() {
        let missing = key_only(&KEY);
        let short = key_and_iv(&KEY, &[0; 15]);
        let empty = key_and_iv(&KEY, &[]);
        let long = key_and_iv(&KEY, &[0; 17]);

        for name in [
            "AES/CBC/NOPADDING",
            "AES/CBC/PKCS7PADDING",
            "AES/CFB/NOPADDING",
            "AES/OFB/NOPADDING",
        ] {
            let params: [&dyn Params; 4] = [&missing, &short, &empty, &long];
            for params in params {
                assert_eq!(init_error(name, params), ErrorKind::InvalidParams);
            }
        }
    }

    #[test]
    fn init_refuses_a_key_or_an_iv_of_the_wrong_length() {
        assert_eq!(
            init_error("AES/ECB/NOPADDING", &key_only(&KEY[..15])),
            ErrorKind::InvalidParams
        );
        assert_eq!(
            init_error("AES/CBC/NOPADDING", &key_and_iv(&KEY[..15], &CBC_IV)),
            ErrorKind::InvalidParams
        );
    }

    struct OtherParams;

    impl Params for OtherParams {
        fn as_any(&self) -> &dyn core::any::Any {
            self
        }
    }

    #[test]
    fn init_refuses_params_of_another_type() {
        assert_eq!(
            init_error("AES/ECB/NOPADDING", &OtherParams),
            ErrorKind::InvalidParams
        );
    }

    #[test]
    fn a_new_builder_finds_the_row_by_its_name_whatever_the_case() {
        let algo = DefaultAlgoBuilder::default().build();
        assert!(algo.cipher().get_by_name("AES/ECB/NoPadding").is_ok());
        assert!(algo.cipher().get_by_name("aes/ecb/nopadding").is_ok());
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

    const GCM: &str = "AES/GCM/NOPADDING";

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    // Test Case 4 of the GCM specification
    fn gcm_params() -> AeadParamsOwned {
        AeadParamsOwned::new(
            hex("feffe9928665731c6d6a8f9467308308"),
            hex("cafebabefacedbaddecaf888"),
            16,
            hex("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
        )
    }

    fn gcm_plaintext() -> Vec<u8> {
        hex(concat!(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        ))
    }

    fn gcm_sealed() -> Vec<u8> {
        hex(concat!(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e",
            "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
            "5bc94fbc3221a5db94fae95ae7121a47",
        ))
    }

    #[test]
    fn the_gcm_row_gives_the_standard_ciphertext_and_tag_through_the_helpers() {
        let algo = DefaultAlgoBuilder::default().build();
        let sealed = algo
            .cipher()
            .encrypt_by_name(GCM, &gcm_params(), &gcm_plaintext())
            .unwrap();
        assert_eq!(sealed, gcm_sealed());
        let opened = algo
            .cipher()
            .decrypt_by_name(GCM, &gcm_params(), &sealed)
            .unwrap();
        assert_eq!(opened, gcm_plaintext());
    }

    #[test]
    fn the_gcm_helpers_report_a_changed_ciphertext_or_a_changed_aad_as_invalid_ciphertext() {
        let algo = DefaultAlgoBuilder::default().build();
        let mut changed = gcm_sealed();
        changed[0] ^= 1;
        let error = algo
            .cipher()
            .decrypt_by_name(GCM, &gcm_params(), &changed)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidCiphertext);

        let other_aad = AeadParamsOwned::new(
            hex("feffe9928665731c6d6a8f9467308308"),
            hex("cafebabefacedbaddecaf888"),
            16,
            vec![],
        );
        let error = algo
            .cipher()
            .decrypt_by_name(GCM, &other_aad, &gcm_sealed())
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidCiphertext);
    }

    #[test]
    fn the_gcm_row_reports_a_ciphertext_shorter_than_the_tag_as_invalid_ciphertext() {
        let algo = DefaultAlgoBuilder::default().build();
        let error = algo
            .cipher()
            .decrypt_by_name(GCM, &gcm_params(), &[0; 15])
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidCiphertext);
    }

    #[test]
    fn the_gcm_row_refuses_params_of_another_type_or_a_key_of_the_wrong_length() {
        assert_eq!(
            init_error(GCM, &key_and_iv(&KEY, &CBC_IV)),
            ErrorKind::InvalidParams
        );
        let short_key = AeadParamsOwned::new(KEY[..15].to_vec(), vec![0; 12], 16, vec![]);
        assert_eq!(init_error(GCM, &short_key), ErrorKind::InvalidParams);
    }

    #[test]
    fn the_gcm_row_reports_a_cipher_that_was_not_initialized() {
        let mut cipher = entry(GCM).create();
        let error = cipher.update(&PLAINTEXT).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
        let error = cipher.finalize().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
    }

    #[test]
    fn a_finished_gcm_encryption_refuses_more_data_and_the_same_nonce() {
        let mut cipher = entry(GCM).create();
        cipher
            .init(CipherDirection::Encrypt, &gcm_params())
            .unwrap();
        cipher.finalize().unwrap();
        let error = cipher.update(&PLAINTEXT).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
        let error = cipher
            .init(CipherDirection::Encrypt, &gcm_params())
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}
