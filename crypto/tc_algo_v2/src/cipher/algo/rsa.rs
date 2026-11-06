use core::error::Error;

use rand_core::CryptoRng;
use tc_asn1::Asn1Oid;
use tc_asym_encoding::{EncodingError, OaepEncoding, Pkcs1Encoding};
use tc_buffered_cipher::{
    BufferedAsymmetricBlockCipher, BufferedCipher, BufferedCipherInit, BufferedError,
    CipherDirection as BufferedDirection,
};
use tc_rsa::{RsaBlindedEngine, RsaEngine, RsaError, RsaKey};
use tc_sha::{Sha1Digest, Sha256Digest};

use crate::cipher::{Cipher, CipherDirection, CipherEntry};
use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind, Params};

type Rand = fn() -> Box<dyn CryptoRng>;

// The rows of RSA, to give to DefaultAlgoBuilder::reg_cipher. Their names and OIDs are those of
// Bouncy Castle's CipherUtilities, where a name may give the mode as NONE or ECB, or leave it out,
// and where rsaEncryption is PKCS#1 v1.5 and id-RSAES-OAEP is OAEP with SHA-1
pub(super) fn rsa(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand = context.rand();
    vec![
        row("RSA", &["NOPADDING"], &[], rand, |rand| {
            Box::new(Rsa(BufferedAsymmetricBlockCipher::new(engine(rand))))
        }),
        row(
            "RSA//PKCS1PADDING",
            &["PKCS1PADDING", "PKCS1"],
            &["1.2.840.113549.1.1.1"],
            rand,
            |rand| {
                let encoding = Pkcs1Encoding::from_parts(engine(rand), rand());
                Box::new(Rsa(BufferedAsymmetricBlockCipher::new(encoding)))
            },
        ),
        row(
            "RSA//OAEPPADDING",
            &[
                "OAEPPADDING",
                "OAEP",
                "OAEPWITHSHA1ANDMGF1PADDING",
                "OAEPWITHSHA-1ANDMGF1PADDING",
            ],
            &["1.2.840.113549.1.1.7"],
            rand,
            |rand| {
                let encoding = OaepEncoding::from_parts(engine(rand), Sha1Digest::new(), rand());
                Box::new(Rsa(BufferedAsymmetricBlockCipher::new(encoding)))
            },
        ),
        row(
            "RSA//OAEPWITHSHA256ANDMGF1PADDING",
            &[
                "OAEPWITHSHA256ANDMGF1PADDING",
                "OAEPWITHSHA-256ANDMGF1PADDING",
                "OAEPWITHSHA256ANDMGF1WITHSHA256PADDING",
                "OAEPWITHSHA-256ANDMGF1WITHSHA-256PADDING",
            ],
            &[],
            rand,
            |rand| {
                let encoding = OaepEncoding::from_parts(engine(rand), Sha256Digest::new(), rand());
                Box::new(Rsa(BufferedAsymmetricBlockCipher::new(encoding)))
            },
        ),
    ]
}

// Blinded, as Bouncy Castle's CipherUtilities builds RSA, so that the private power never works on
// the ciphertext itself
fn engine(rand: Rand) -> RsaBlindedEngine<RsaEngine, Box<dyn CryptoRng>> {
    RsaBlindedEngine::from_parts(RsaEngine::new(), rand())
}

fn row(
    name: &'static str,
    paddings: &[&str],
    oids: &[&str],
    rand: Rand,
    create: fn(Rand) -> Box<dyn Cipher>,
) -> Box<dyn CipherEntry> {
    let aliases = ["RSA//", "RSA/NONE/", "RSA/ECB/"]
        .iter()
        .flat_map(|mode| {
            paddings
                .iter()
                .map(move |padding| format!("{mode}{padding}"))
        })
        .filter(|alias| alias != name)
        .collect();
    Box::new(Row {
        name,
        aliases,
        oids: oids
            .iter()
            .map(|dotted| dotted.parse().expect("a valid OID"))
            .collect(),
        rand,
        create,
    })
}

struct Row {
    name: &'static str,
    aliases: Vec<String>,
    oids: Vec<Asn1Oid>,
    rand: Rand,
    create: fn(Rand) -> Box<dyn Cipher>,
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
        (self.create)(self.rand)
    }
}

// Its params are an RsaKey, public or private, in either direction, as in Bouncy Castle. One message
// is one block, so nothing comes out before do_final
struct Rsa<C>(C);

impl<C, E, I> Cipher for Rsa<C>
where
    C: BufferedCipher<Error = BufferedError<E>> + BufferedCipherInit<RsaKey, Error = I>,
    E: Kind + Error + Send + Sync + 'static,
    I: Error + Send + Sync + 'static,
{
    fn init(&mut self, direction: CipherDirection, params: &dyn Params) -> Result<(), AlgoError> {
        let key = params
            .as_any()
            .downcast_ref::<RsaKey>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        let direction = match direction {
            CipherDirection::Encrypt => BufferedDirection::Encrypt,
            CipherDirection::Decrypt => BufferedDirection::Decrypt,
        };
        self.0
            .init(direction, key)
            .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))
    }

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

trait Kind {
    fn kind(&self) -> ErrorKind;
}

impl Kind for RsaError {
    fn kind(&self) -> ErrorKind {
        match self {
            RsaError::NotInitialized => ErrorKind::NotInitialized,
            RsaError::InputTooSmall | RsaError::InputTooLarge | RsaError::OutputTooShort => {
                ErrorKind::DataLength
            }
            _ => ErrorKind::InvalidParams,
        }
    }
}

impl<E: Kind> Kind for EncodingError<E> {
    fn kind(&self) -> ErrorKind {
        match self {
            EncodingError::Cipher(error) => error.kind(),
            EncodingError::NotInitialized => ErrorKind::NotInitialized,
            // A block that is not a valid PKCS#1 or OAEP encoding
            EncodingError::InvalidBlock => ErrorKind::InvalidCiphertext,
            _ => ErrorKind::DataLength,
        }
    }
}

fn algo_error<E: Kind + Error + Send + Sync + 'static>(error: BufferedError<E>) -> AlgoError {
    let kind = match &error {
        BufferedError::NotInitialized => ErrorKind::NotInitialized,
        BufferedError::Cipher(error) => error.kind(),
        _ => ErrorKind::DataLength,
    };
    AlgoError::with_source(kind, error)
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use rand::rngs::SysRng;
    use rand_core::UnwrapErr;
    use tc_asym_encoding::{OaepEncoding, Pkcs1Encoding};
    use tc_buffered_cipher::{
        BufferedAsymmetricBlockCipher, BufferedCipher, BufferedCipherInit, CipherDirection as Dir,
    };
    use tc_rsa::{RsaEngine, RsaKey};
    use tc_sha::Sha256Digest;

    use crate::cipher::CipherDirection;
    use crate::params::{KeyLength, RsaKeyGenerationParamsOwned};
    use crate::{Algo, AlgoBuilder, DefaultAlgoBuilder, ErrorKind};

    const PKCS1: &str = "RSA//PKCS1PADDING";
    const OAEP_SHA1: &str = "RSA//OAEPPADDING";
    const OAEP_SHA256: &str = "RSA//OAEPWITHSHA256ANDMGF1PADDING";
    const MESSAGE: &[u8] = b"attack at dawn";

    fn algo() -> Box<dyn Algo> {
        DefaultAlgoBuilder::default().build()
    }

    // One pair for all the tests, since generating the primes is slow
    fn keys() -> &'static (RsaKey, RsaKey) {
        static KEYS: OnceLock<(RsaKey, RsaKey)> = OnceLock::new();
        KEYS.get_or_init(|| {
            let params = RsaKeyGenerationParamsOwned::new(UnwrapErr(SysRng)).with_strength(1024);
            let pair = algo()
                .key_pair_generator()
                .generate_by_name_with("RSA", &params)
                .unwrap();
            let key = |params: &dyn crate::Params| {
                params.as_any().downcast_ref::<RsaKey>().unwrap().clone()
            };
            (key(pair.public()), key(pair.private()))
        })
    }

    #[test]
    fn a_key_pair_from_the_generator_goes_straight_into_the_helpers() {
        let params = RsaKeyGenerationParamsOwned::new(UnwrapErr(SysRng)).with_strength(1024);
        let algo = algo();
        let pair = algo
            .key_pair_generator()
            .generate_by_name_with("RSA", &params)
            .unwrap();

        let sealed = algo
            .cipher()
            .encrypt_by_name(PKCS1, pair.public(), MESSAGE)
            .unwrap();
        let opened = algo
            .cipher()
            .decrypt_by_name(PKCS1, pair.private(), &sealed)
            .unwrap();
        assert_eq!(opened, MESSAGE);
    }

    #[test]
    fn the_padded_rows_take_back_what_they_encrypted_by_any_of_their_names() {
        let (public, private) = keys();
        let algo = algo();
        for name in [
            PKCS1,
            "RSA/ECB/PKCS1",
            "rsa/none/pkcs1padding",
            OAEP_SHA1,
            "RSA//OAEP",
            "RSA/ECB/OAEPWITHSHA-1ANDMGF1PADDING",
            OAEP_SHA256,
            "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING",
        ] {
            let sealed = algo
                .cipher()
                .encrypt_by_name(name, public, MESSAGE)
                .unwrap();
            assert_eq!(sealed.len(), 128, "{name}");
            let opened = algo
                .cipher()
                .decrypt_by_name(name, private, &sealed)
                .unwrap();
            assert_eq!(opened, MESSAGE, "{name}");
        }
    }

    #[test]
    fn the_row_without_padding_gives_back_a_whole_block() {
        let (public, private) = keys();
        let algo = algo();
        for name in ["RSA", "RSA/ECB/NOPADDING", "RSA//NOPADDING"] {
            let sealed = algo
                .cipher()
                .encrypt_by_name(name, public, MESSAGE)
                .unwrap();
            let opened = algo
                .cipher()
                .decrypt_by_name(name, private, &sealed)
                .unwrap();
            assert!(opened.ends_with(MESSAGE), "{name}");
        }
    }

    #[test]
    fn the_oids_find_pkcs1_and_oaep_with_sha1() {
        let (public, private) = keys();
        let algo = algo();
        for (dotted, name) in [
            ("1.2.840.113549.1.1.1", PKCS1),
            ("1.2.840.113549.1.1.7", OAEP_SHA1),
        ] {
            let oid = dotted.parse().unwrap();
            let sealed = algo.cipher().encrypt_by_oid(&oid, public, MESSAGE).unwrap();
            let opened = algo
                .cipher()
                .decrypt_by_name(name, private, &sealed)
                .unwrap();
            assert_eq!(opened, MESSAGE);
        }
    }

    #[test]
    fn the_rows_use_the_encodings_they_name() {
        let (public, private) = keys();
        let algo = algo();
        let rng = || UnwrapErr(SysRng);
        let mut opened = [0; 128];

        let sealed = algo
            .cipher()
            .encrypt_by_name(PKCS1, public, MESSAGE)
            .unwrap();
        let encoding = Pkcs1Encoding::from_parts(RsaEngine::new(), rng());
        let mut cipher = BufferedAsymmetricBlockCipher::new(encoding);
        cipher.init(Dir::Decrypt, private).unwrap();
        cipher.process_bytes(&sealed, &mut []).unwrap();
        let written = cipher.do_final(&mut opened).unwrap();
        assert_eq!(&opened[..written], MESSAGE);

        let sealed = algo
            .cipher()
            .encrypt_by_name(OAEP_SHA256, public, MESSAGE)
            .unwrap();
        let encoding = OaepEncoding::from_parts(RsaEngine::new(), Sha256Digest::new(), rng());
        let mut cipher = BufferedAsymmetricBlockCipher::new(encoding);
        cipher.init(Dir::Decrypt, private).unwrap();
        cipher.process_bytes(&sealed, &mut []).unwrap();
        let written = cipher.do_final(&mut opened).unwrap();
        assert_eq!(&opened[..written], MESSAGE);

        // OAEP under one digest is not valid under the other
        let error = algo
            .cipher()
            .decrypt_by_name(OAEP_SHA1, private, &sealed)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidCiphertext);
    }

    #[test]
    fn a_changed_ciphertext_is_invalid_ciphertext() {
        let (public, private) = keys();
        let algo = algo();
        for name in [PKCS1, OAEP_SHA1, OAEP_SHA256] {
            let mut sealed = algo
                .cipher()
                .encrypt_by_name(name, public, MESSAGE)
                .unwrap();
            sealed[127] ^= 1;
            let error = algo
                .cipher()
                .decrypt_by_name(name, private, &sealed)
                .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidCiphertext, "{name}");
        }
    }

    #[test]
    fn a_message_too_long_for_the_key_is_data_length() {
        let (public, _) = keys();
        let algo = algo();
        for name in [PKCS1, OAEP_SHA1, OAEP_SHA256] {
            let error = algo
                .cipher()
                .encrypt_by_name(name, public, &[0x5a; 200])
                .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::DataLength, "{name}");
        }
    }

    #[test]
    fn the_sizes_come_from_the_key_and_nothing_comes_out_before_do_final() {
        let (public, _) = keys();
        let mut cipher = algo().cipher().get_by_name(PKCS1).unwrap();
        cipher.init(CipherDirection::Encrypt, public).unwrap();
        assert_eq!(cipher.output_len(MESSAGE.len()).unwrap(), 128);
        assert!(cipher.update(MESSAGE).unwrap().is_empty());
        assert_eq!(cipher.finalize().unwrap().len(), 128);
    }

    #[test]
    fn init_refuses_params_of_another_type() {
        let mut cipher = algo().cipher().get_by_name(PKCS1).unwrap();
        let error = cipher
            .init(CipherDirection::Encrypt, &KeyLength::new(16))
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }

    #[test]
    fn update_and_finalize_report_a_cipher_that_was_not_initialized() {
        let mut cipher = algo().cipher().get_by_name(PKCS1).unwrap();
        let error = cipher.update(MESSAGE).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
        let error = cipher.finalize().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
    }
}
