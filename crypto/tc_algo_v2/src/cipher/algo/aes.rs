use core::error::Error;

use tc_aes::AesEngine;
use tc_asn1::Asn1Oid;
use tc_block_modes::{CbcBlockCipher, EcbBlockCipher};
use tc_buffered_cipher::{
    BufferedBlockCipher, BufferedCipher, BufferedError, PaddedBufferedBlockCipher,
};

use crate::cipher::{Cipher, CipherDirection, CipherEntry};
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

// Puts a buffered cipher, whatever its mode and padding, behind Cipher
struct Buffered<C>(C);

impl<C, E> Cipher for Buffered<C>
where
    C: BufferedCipher<Error = BufferedError<E>>,
    E: Error + Send + Sync + 'static,
{
    fn init(&mut self, _direction: CipherDirection, _params: &dyn Params) -> Result<(), AlgoError> {
        todo!()
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
    use tc_block_cipher::KeyRef;
    use tc_buffered_cipher::{BufferedBlockCipher, BufferedCipherInit, CipherDirection};

    use super::{Buffered, aes, ecb};
    use crate::cipher::{Cipher, CipherEntry};
    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind};

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

    // Goes around Cipher::init, which cannot take a key from Params yet
    fn keyed(direction: CipherDirection) -> impl Cipher {
        let mut cipher = BufferedBlockCipher::new(ecb());
        cipher.init(direction, &KeyRef::new(&KEY)).unwrap();
        Buffered(cipher)
    }

    fn ecb_no_padding() -> Box<dyn CipherEntry> {
        aes()
            .into_iter()
            .find(|row| row.name() == "AES/ECB/NOPADDING")
            .expect("the row of AES/ECB/NOPADDING")
    }

    #[test]
    fn the_row_has_no_aliases_or_oids() {
        let entry = ecb_no_padding();
        assert!(entry.aliases().is_empty());
        assert!(entry.oids().is_empty());
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
        let mut cipher = ecb_no_padding().create();
        let error = cipher.update(&PLAINTEXT).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
        let error = cipher.finalize().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
    }
}
