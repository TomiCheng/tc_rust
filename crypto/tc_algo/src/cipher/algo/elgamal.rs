use core::error::Error;

use rand_core::CryptoRng;
use tc_asym_encoding::{OaepEncoding, Pkcs1Encoding};
use tc_buffered_cipher::{BufferedAsymmetricBlockCipher, BufferedCipherInit};
use tc_digest::Digest;
use tc_elgamal::{ElGamalEngine, ElGamalError, ElGamalPrivateKey, ElGamalPublicKey};
use tc_md::Md5Digest;
use tc_sha::{Sha1Digest, Sha224Digest, Sha256Digest, Sha384Digest, Sha512Digest};

use super::asym::{Asym, Keys, Kind, Rand, invalid_params, row};
use crate::cipher::{Cipher, CipherDirection, CipherEntry};
use crate::{AlgoError, DefaultAlgoContext, ErrorKind, Params};

// The rows of ElGamal, to give to DefaultAlgoBuilder::reg_cipher, with the paddings of Bouncy
// Castle's CipherUtilities, which has no OID for it. ISO 9796-1 is RSA's alone: Bouncy Castle's
// encoding takes an RSA key, and tc_asym_iso9796 is built on RSA
pub(super) fn elgamal(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand = context.rand();
    vec![
        row(
            "ELGAMAL",
            "ELGAMAL",
            &["NOPADDING", "RAW"],
            &[],
            rand,
            |rand| {
                Box::new(Asym::<_, ElGamalKeys>::new(
                    BufferedAsymmetricBlockCipher::new(engine(rand)),
                ))
            },
        ),
        row(
            "ELGAMAL",
            "ELGAMAL//PKCS1PADDING",
            &["PKCS1PADDING", "PKCS1"],
            &[],
            rand,
            |rand| {
                let encoding = Pkcs1Encoding::from_parts(engine(rand), rand());
                Box::new(Asym::<_, ElGamalKeys>::new(
                    BufferedAsymmetricBlockCipher::new(encoding),
                ))
            },
        ),
        row(
            "ELGAMAL",
            "ELGAMAL//OAEPPADDING",
            &[
                "OAEPPADDING",
                "OAEP",
                "OAEPWITHSHA1ANDMGF1PADDING",
                "OAEPWITHSHA-1ANDMGF1PADDING",
            ],
            &[],
            rand,
            |rand| oaep(Sha1Digest::new(), rand),
        ),
        row(
            "ELGAMAL",
            "ELGAMAL//OAEPWITHMD5ANDMGF1PADDING",
            &["OAEPWITHMD5ANDMGF1PADDING"],
            &[],
            rand,
            |rand| oaep(Md5Digest::new(), rand),
        ),
        row(
            "ELGAMAL",
            "ELGAMAL//OAEPWITHSHA224ANDMGF1PADDING",
            &[
                "OAEPWITHSHA224ANDMGF1PADDING",
                "OAEPWITHSHA-224ANDMGF1PADDING",
            ],
            &[],
            rand,
            |rand| oaep(Sha224Digest::new(), rand),
        ),
        row(
            "ELGAMAL",
            "ELGAMAL//OAEPWITHSHA256ANDMGF1PADDING",
            &[
                "OAEPWITHSHA256ANDMGF1PADDING",
                "OAEPWITHSHA-256ANDMGF1PADDING",
                "OAEPWITHSHA256ANDMGF1WITHSHA256PADDING",
                "OAEPWITHSHA-256ANDMGF1WITHSHA-256PADDING",
            ],
            &[],
            rand,
            |rand| oaep(Sha256Digest::new(), rand),
        ),
        row(
            "ELGAMAL",
            "ELGAMAL//OAEPWITHSHA256ANDMGF1WITHSHA1PADDING",
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
                Box::new(Asym::<_, ElGamalKeys>::new(
                    BufferedAsymmetricBlockCipher::new(encoding),
                ))
            },
        ),
        row(
            "ELGAMAL",
            "ELGAMAL//OAEPWITHSHA384ANDMGF1PADDING",
            &[
                "OAEPWITHSHA384ANDMGF1PADDING",
                "OAEPWITHSHA-384ANDMGF1PADDING",
            ],
            &[],
            rand,
            |rand| oaep(Sha384Digest::new(), rand),
        ),
        row(
            "ELGAMAL",
            "ELGAMAL//OAEPWITHSHA512ANDMGF1PADDING",
            &[
                "OAEPWITHSHA512ANDMGF1PADDING",
                "OAEPWITHSHA-512ANDMGF1PADDING",
            ],
            &[],
            rand,
            |rand| oaep(Sha512Digest::new(), rand),
        ),
    ]
}

fn engine(rand: Rand) -> ElGamalEngine<Box<dyn CryptoRng>> {
    ElGamalEngine::new(rand())
}

fn oaep<D: Digest + 'static>(digest: D, rand: Rand) -> Box<dyn Cipher> {
    let encoding = OaepEncoding::from_parts(engine(rand), digest, rand());
    Box::new(Asym::<_, ElGamalKeys>::new(
        BufferedAsymmetricBlockCipher::new(encoding),
    ))
}

// An ElGamalPublicKey to encrypt or an ElGamalPrivateKey to decrypt; the engine refuses the other
// way round
struct ElGamalKeys;

impl<C, I, J> Keys<C> for ElGamalKeys
where
    C: BufferedCipherInit<ElGamalPublicKey, Error = I>
        + BufferedCipherInit<ElGamalPrivateKey, Error = J>,
    I: Error + Send + Sync + 'static,
    J: Error + Send + Sync + 'static,
{
    fn init(
        cipher: &mut C,
        direction: CipherDirection,
        params: &dyn Params,
    ) -> Result<(), AlgoError> {
        let params = params.as_any();
        if let Some(key) = params.downcast_ref::<ElGamalPublicKey>() {
            return cipher.init(direction, key).map_err(invalid_params);
        }
        let key = params
            .downcast_ref::<ElGamalPrivateKey>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        cipher.init(direction, key).map_err(invalid_params)
    }
}

impl Kind for ElGamalError {
    fn kind(&self) -> ErrorKind {
        match self {
            ElGamalError::NotInitialized => ErrorKind::NotInitialized,
            // A ciphertext whose halves are not in the group
            ElGamalError::WeakCiphertext => ErrorKind::InvalidCiphertext,
            ElGamalError::InputTooLarge
            | ElGamalError::InputTooSmall
            | ElGamalError::InvalidCiphertextLength
            | ElGamalError::OutputTooShort => ErrorKind::DataLength,
            _ => ErrorKind::InvalidParams,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use rand::rngs::SysRng;
    use rand_core::UnwrapErr;

    use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
    use tc_dh_key::standard_groups::rfc3526_1536;
    use tc_elgamal::{
        ElGamalKeyGenerationParams, ElGamalKeyPairGenerator, ElGamalParameters, ElGamalPrivateKey,
        ElGamalPublicKey,
    };

    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind};

    const MESSAGE: &[u8] = b"attack at dawn";

    // One pair over the 1536-bit group of RFC 3526 for all the tests
    fn keys() -> &'static (ElGamalPublicKey, ElGamalPrivateKey) {
        static KEYS: OnceLock<(ElGamalPublicKey, ElGamalPrivateKey)> = OnceLock::new();
        KEYS.get_or_init(|| {
            let group = rfc3526_1536();
            let params = ElGamalParameters::new(group.p().clone(), group.g().clone());
            let mut generator = ElGamalKeyPairGenerator::new(UnwrapErr(SysRng));
            generator
                .init(&ElGamalKeyGenerationParams::new(params))
                .unwrap();
            generator.generate_key_pair().unwrap()
        })
    }

    #[test]
    fn every_padding_decrypts_what_it_encrypted_by_any_of_its_names() {
        let (public, private) = keys();
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();
        for name in [
            "ELGAMAL//PKCS1PADDING",
            "ElGamal/ECB/PKCS1",
            "ELGAMAL//OAEPPADDING",
            "ELGAMAL/NONE/OAEPWITHSHA-1ANDMGF1PADDING",
            "ELGAMAL//OAEPWITHMD5ANDMGF1PADDING",
            "ELGAMAL//OAEPWITHSHA-224ANDMGF1PADDING",
            "ELGAMAL//OAEPWITHSHA256ANDMGF1PADDING",
            "ELGAMAL//OAEPWITHSHA-256ANDMGF1WITHSHA-1PADDING",
            "ELGAMAL//OAEPWITHSHA384ANDMGF1PADDING",
            "ELGAMAL//OAEPWITHSHA-512ANDMGF1PADDING",
        ] {
            let sealed = ciphers.encrypt_by_name(name, public, MESSAGE).unwrap();
            // Two halves of the size of p
            assert_eq!(sealed.len(), 2 * 192, "{name}");
            let opened = ciphers.decrypt_by_name(name, private, &sealed).unwrap();
            assert_eq!(opened, MESSAGE, "{name}");
        }
    }

    #[test]
    fn the_row_without_padding_gives_back_the_message_as_a_number() {
        let (public, private) = keys();
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();
        for name in ["ELGAMAL", "ELGAMAL//NOPADDING", "ELGAMAL/ECB/RAW"] {
            let sealed = ciphers.encrypt_by_name(name, public, MESSAGE).unwrap();
            let opened = ciphers.decrypt_by_name(name, private, &sealed).unwrap();
            assert!(opened.ends_with(MESSAGE), "{name}");
        }
    }

    #[test]
    fn a_changed_ciphertext_and_a_key_of_another_type_are_refused() {
        let (public, private) = keys();
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();
        let name = "ELGAMAL//OAEPPADDING";
        let mut sealed = ciphers.encrypt_by_name(name, public, MESSAGE).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        let error = ciphers.decrypt_by_name(name, private, &sealed).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidCiphertext);

        let error = ciphers
            .encrypt_by_name(name, &crate::params::KeyOwned::new(vec![0; 16]), MESSAGE)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}
