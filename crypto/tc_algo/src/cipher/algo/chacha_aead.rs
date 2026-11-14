use core::error::Error;

use tc_aead_cipher::{AeadCipher, AeadCipherInit, AeadError, AeadParamsOwned};
use tc_asn1::Asn1Oid;
#[cfg(feature = "chacha20-poly1305")]
use tc_chacha_aead::ChaCha20Poly1305Engine;
#[cfg(feature = "xchacha20-poly1305")]
use tc_chacha_aead::XChaCha20Poly1305Engine;

use crate::cipher::{BufferedCipher, Cipher, CipherDirection, CipherEntry};
use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind, Params};

// ChaCha20-Poly1305 of RFC 8439, as Bouncy Castle's CipherUtilities names it, with the OID of RFC
// 8103 that it gives the same row
#[cfg(feature = "chacha20-poly1305")]
pub(super) fn chacha20_poly1305(_: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![row(
        "CHACHA20-POLY1305",
        &["1.2.840.113549.1.9.16.3.18"],
        || Box::new(ChaChaAead(ChaCha20Poly1305Engine::new())),
    )]
}

// XChaCha20-Poly1305, its extension to a nonce of 24 bytes, as Bouncy Castle names it, with no OID
#[cfg(feature = "xchacha20-poly1305")]
pub(super) fn xchacha20_poly1305(_: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![row("XCHACHA20-POLY1305", &[], || {
        Box::new(ChaChaAead(XChaCha20Poly1305Engine::new()))
    })]
}

fn row(name: &'static str, oids: &[&str], create: fn() -> Box<dyn Cipher>) -> Box<dyn CipherEntry> {
    Box::new(Row {
        name,
        oids: oids
            .iter()
            .map(|dotted| dotted.parse().expect("a valid OID"))
            .collect(),
        create,
    })
}

struct Row {
    name: &'static str,
    oids: Vec<Asn1Oid>,
    create: fn() -> Box<dyn Cipher>,
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        self.name
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

// An AEAD engine of tc_chacha_aead behind Cipher. Its params are an AeadParamsOwned, with a key of
// 32 bytes and a tag of 16. Encryption ends with the tag, and decryption expects it at the end of
// the input; as in Bouncy Castle, update may give plaintext before finalize has checked the tag
struct ChaChaAead<C>(C);

impl<C> BufferedCipher for ChaChaAead<C>
where
    C: AeadCipher<Error = AeadError>,
{
    type Error = AlgoError;

    // Zero, as for a stream cipher
    fn block_size(&self) -> usize {
        0
    }

    fn update_output_len(&self, input_len: usize) -> Result<usize, AlgoError> {
        self.0.update_output_len(input_len).map_err(aead_error)
    }

    fn output_len(&self, input_len: usize) -> Result<usize, AlgoError> {
        self.0.output_len(input_len).map_err(aead_error)
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, AlgoError> {
        self.0.process_bytes(input, output).map_err(aead_error)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        self.0.do_final(output).map_err(aead_error)
    }

    fn reset(&mut self) {
        self.0.reset();
    }
}

impl<C, I> Cipher for ChaChaAead<C>
where
    C: AeadCipher<Error = AeadError> + AeadCipherInit<AeadParamsOwned, Error = I>,
    I: Error + Send + Sync + 'static,
{
    fn init(&mut self, direction: CipherDirection, params: &dyn Params) -> Result<(), AlgoError> {
        let params = params
            .as_any()
            .downcast_ref::<AeadParamsOwned>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        self.0
            .init(direction.into(), params)
            .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))
    }
}

fn aead_error(error: AeadError) -> AlgoError {
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
    use crate::params::AeadParamsOwned;
    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind};

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    // RFC 8439, section 2.8.2: the sunscreen message, sealed with its tag
    #[cfg(feature = "chacha20-poly1305")]
    #[test]
    fn chacha20_poly1305_gives_the_example_of_rfc_8439() {
        let params = AeadParamsOwned::new(
            unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
            unhex("070000004041424344454647"),
            16,
            unhex("50515253c0c1c2c3c4c5c6c7"),
        );
        let message = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();
        let sealed = ciphers
            .encrypt_by_name("ChaCha20-Poly1305", &params, message)
            .unwrap();
        assert_eq!(
            &sealed[message.len()..],
            unhex("1ae10b594f09e26a7e902ecbd0600691").as_slice()
        );
        assert_eq!(
            &sealed[..16],
            unhex("d31a8d34648e60db7b86afbc53ef7ec2").as_slice()
        );
        let opened = ciphers
            .decrypt_by_name("CHACHA20-POLY1305", &params, &sealed)
            .unwrap();
        assert_eq!(opened, message);

        let by_oid = ciphers
            .get_by_oid(&"1.2.840.113549.1.9.16.3.18".parse().unwrap())
            .unwrap();
        assert_eq!(by_oid.block_size(), 0);

        let mut changed = sealed.clone();
        changed[0] ^= 1;
        let error = ciphers
            .decrypt_by_name("CHACHA20-POLY1305", &params, &changed)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidCiphertext);
    }

    // A nonce of 24 bytes, which may be drawn at random; one of 12 is refused
    #[cfg(feature = "xchacha20-poly1305")]
    #[test]
    fn xchacha20_poly1305_takes_a_nonce_of_24_bytes_and_decrypts_back() {
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();
        let params = AeadParamsOwned::new(vec![0x42; 32], vec![0x24; 24], 16, b"aad".to_vec());
        let sealed = ciphers
            .encrypt_by_name("XCHACHA20-POLY1305", &params, b"message")
            .unwrap();
        assert_eq!(sealed.len(), 7 + 16);
        let opened = ciphers
            .decrypt_by_name("xchacha20-poly1305", &params, &sealed)
            .unwrap();
        assert_eq!(opened, b"message");

        let short = AeadParamsOwned::new(vec![0x42; 32], vec![0x24; 12], 16, Vec::new());
        let error = ciphers
            .encrypt_by_name("XCHACHA20-POLY1305", &short, b"message")
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}
