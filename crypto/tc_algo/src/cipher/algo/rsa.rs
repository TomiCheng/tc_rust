use core::error::Error;

use rand_core::CryptoRng;
use tc_asym_encoding::{OaepEncoding, Pkcs1Encoding};
use tc_asym_iso9796::{Iso9796Error, Iso9796d1Encoding};
use tc_buffered_cipher::{BufferedAsymmetricBlockCipher, BufferedCipherInit};
use tc_md::Md5Digest;
use tc_rsa::{RsaBlindedEngine, RsaEngine, RsaError, RsaKey};
use tc_sha::{Sha1Digest, Sha224Digest, Sha256Digest, Sha384Digest, Sha512Digest};

use super::asym::{Asym, Keys, Kind, Rand, invalid_params, row};
use crate::cipher::{CipherDirection, CipherEntry};
use crate::{AlgoError, DefaultAlgoContext, ErrorKind, Params};

// The rows of RSA, to give to DefaultAlgoBuilder::reg_cipher. Their names and OIDs are those of
// Bouncy Castle's CipherUtilities, where a name may give the mode as NONE or ECB, or leave it out,
// and where rsaEncryption is PKCS#1 v1.5 and id-RSAES-OAEP is OAEP with SHA-1. OAEP takes one digest
// for the label and MGF1, but SHA-256 with MGF1 over SHA-1, for the data of Java's default
pub(super) fn rsa(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand = context.rand();
    vec![
        row("RSA", "RSA", &["NOPADDING", "RAW"], &[], rand, |rand| {
            Box::new(Asym::<_, RsaKeys>::new(BufferedAsymmetricBlockCipher::new(
                engine(rand),
            )))
        }),
        row(
            "RSA",
            "RSA//PKCS1PADDING",
            &["PKCS1PADDING", "PKCS1"],
            &["1.2.840.113549.1.1.1"],
            rand,
            |rand| {
                let encoding = Pkcs1Encoding::from_parts(engine(rand), rand());
                Box::new(Asym::<_, RsaKeys>::new(BufferedAsymmetricBlockCipher::new(
                    encoding,
                )))
            },
        ),
        row(
            "RSA",
            "RSA//OAEPPADDING",
            &[
                "OAEPPADDING",
                "OAEP",
                "OAEPWITHSHA1ANDMGF1PADDING",
                "OAEPWITHSHA-1ANDMGF1PADDING",
            ],
            &["1.2.840.113549.1.1.7"],
            rand,
            |rand| oaep(engine(rand), Sha1Digest::new(), rand),
        ),
        row(
            "RSA",
            "RSA//OAEPWITHMD5ANDMGF1PADDING",
            &["OAEPWITHMD5ANDMGF1PADDING"],
            &[],
            rand,
            |rand| oaep(engine(rand), Md5Digest::new(), rand),
        ),
        row(
            "RSA",
            "RSA//OAEPWITHSHA224ANDMGF1PADDING",
            &[
                "OAEPWITHSHA224ANDMGF1PADDING",
                "OAEPWITHSHA-224ANDMGF1PADDING",
            ],
            &[],
            rand,
            |rand| oaep(engine(rand), Sha224Digest::new(), rand),
        ),
        row(
            "RSA",
            "RSA//OAEPWITHSHA256ANDMGF1PADDING",
            &[
                "OAEPWITHSHA256ANDMGF1PADDING",
                "OAEPWITHSHA-256ANDMGF1PADDING",
                "OAEPWITHSHA256ANDMGF1WITHSHA256PADDING",
                "OAEPWITHSHA-256ANDMGF1WITHSHA-256PADDING",
            ],
            &[],
            rand,
            |rand| oaep(engine(rand), Sha256Digest::new(), rand),
        ),
        row(
            "RSA",
            "RSA//OAEPWITHSHA256ANDMGF1WITHSHA1PADDING",
            &[
                "OAEPWITHSHA256ANDMGF1WITHSHA1PADDING",
                "OAEPWITHSHA-256ANDMGF1WITHSHA-1PADDING",
            ],
            &[],
            rand,
            |rand| {
                // MGF1 over SHA-1, and SHA-256 for the label, whose hash sets the seed's length
                let encoding = OaepEncoding::from_parts(engine(rand), Sha1Digest::new(), rand())
                    .with_label_digest(Sha256Digest::new(), &[]);
                Box::new(Asym::<_, RsaKeys>::new(BufferedAsymmetricBlockCipher::new(
                    encoding,
                )))
            },
        ),
        row(
            "RSA",
            "RSA//OAEPWITHSHA384ANDMGF1PADDING",
            &[
                "OAEPWITHSHA384ANDMGF1PADDING",
                "OAEPWITHSHA-384ANDMGF1PADDING",
            ],
            &[],
            rand,
            |rand| oaep(engine(rand), Sha384Digest::new(), rand),
        ),
        row(
            "RSA",
            "RSA//OAEPWITHSHA512ANDMGF1PADDING",
            &[
                "OAEPWITHSHA512ANDMGF1PADDING",
                "OAEPWITHSHA-512ANDMGF1PADDING",
            ],
            &[],
            rand,
            |rand| oaep(engine(rand), Sha512Digest::new(), rand),
        ),
        row(
            "RSA",
            "RSA//ISO9796-1PADDING",
            &["ISO9796-1PADDING", "ISO9796-1"],
            &[],
            rand,
            |rand| {
                // Its engine is blinded RSA of its own
                let encoding = Iso9796d1Encoding::new(rand());
                Box::new(Asym::<_, RsaKeys>::new(BufferedAsymmetricBlockCipher::new(
                    encoding,
                )))
            },
        ),
    ]
}

// Blinded, as Bouncy Castle's CipherUtilities builds RSA, so that the private power never works on
// the ciphertext itself
fn engine(rand: Rand) -> RsaBlindedEngine<RsaEngine, Box<dyn CryptoRng>> {
    RsaBlindedEngine::from_parts(RsaEngine::new(), rand())
}

fn oaep<D: tc_digest::Digest + 'static>(
    engine: RsaBlindedEngine<RsaEngine, Box<dyn CryptoRng>>,
    digest: D,
    rand: Rand,
) -> Box<dyn crate::cipher::Cipher> {
    let encoding = OaepEncoding::from_parts(engine, digest, rand());
    Box::new(Asym::<_, RsaKeys>::new(BufferedAsymmetricBlockCipher::new(
        encoding,
    )))
}

// An RsaKey, public or private, in either direction, as in Bouncy Castle
struct RsaKeys;

impl<C, I> Keys<C> for RsaKeys
where
    C: BufferedCipherInit<RsaKey, Error = I>,
    I: Error + Send + Sync + 'static,
{
    fn init(
        cipher: &mut C,
        direction: CipherDirection,
        params: &dyn Params,
    ) -> Result<(), AlgoError> {
        let key = params
            .as_any()
            .downcast_ref::<RsaKey>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        cipher.init(direction, key).map_err(invalid_params)
    }
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

impl Kind for Iso9796Error {
    fn kind(&self) -> ErrorKind {
        match self {
            Iso9796Error::Cipher(error) => error.kind(),
            Iso9796Error::NotInitialized => ErrorKind::NotInitialized,
            // A block that is not a valid ISO 9796-1 encoding
            Iso9796Error::InvalidBlock => ErrorKind::InvalidCiphertext,
            Iso9796Error::UnsupportedKeySize | Iso9796Error::InvalidPadBits => {
                ErrorKind::InvalidParams
            }
            _ => ErrorKind::DataLength,
        }
    }
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
    use crate::params::{generate::KeyLength, generate::RsaKeyGenParams};
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
            let params = RsaKeyGenParams::new(1024);
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
        let params = RsaKeyGenParams::new(1024);
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
            "RSA//OAEPWITHMD5ANDMGF1PADDING",
            "RSA/NONE/OAEPWITHSHA-224ANDMGF1PADDING",
            "RSA//OAEPWITHSHA256ANDMGF1WITHSHA1PADDING",
            "RSA/ECB/OAEPWITHSHA-384ANDMGF1PADDING",
            "RSA//ISO9796-1PADDING",
            "RSA/ECB/ISO9796-1",
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

    // OAEP over SHA-512 spends 130 bytes of the block on its hashes, more than a 1024-bit key has,
    // but takes a 2048-bit one
    #[test]
    fn oaep_over_sha512_needs_a_key_of_more_than_1024_bits() {
        let (public, _) = keys();
        let algo = algo();
        let error = algo
            .cipher()
            .encrypt_by_name("RSA//OAEPWITHSHA512ANDMGF1PADDING", public, MESSAGE)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DataLength);

        let params = RsaKeyGenParams::new(2048);
        let pair = algo
            .key_pair_generator()
            .generate_by_name_with("RSA", &params)
            .unwrap();
        let name = "RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING";
        let sealed = algo
            .cipher()
            .encrypt_by_name(name, pair.public(), MESSAGE)
            .unwrap();
        let opened = algo
            .cipher()
            .decrypt_by_name(name, pair.private(), &sealed)
            .unwrap();
        assert_eq!(opened, MESSAGE);
    }

    // SHA-256 with MGF1 over SHA-1 is not SHA-256 throughout: each opens only its own
    #[test]
    fn oaep_with_mgf1_over_sha1_differs_from_sha256_throughout() {
        let (public, private) = keys();
        let algo = algo();
        let sealed = algo
            .cipher()
            .encrypt_by_name("RSA//OAEPWITHSHA256ANDMGF1WITHSHA1PADDING", public, MESSAGE)
            .unwrap();
        let error = algo
            .cipher()
            .decrypt_by_name(OAEP_SHA256, private, &sealed)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidCiphertext);
    }
}
