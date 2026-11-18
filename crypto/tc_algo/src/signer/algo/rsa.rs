use std::sync::Arc;

use rand_core::CryptoRng;
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asym_cipher::{
    AsymmetricBlockCipher, AsymmetricBlockCipherInit, AsymmetricKeyParams, CipherDirection,
};
use tc_asym_encoding::Pkcs1Encoding;
use tc_constant_time::fixed_time_eq;
use tc_rsa::{RsaBlindedEngine, RsaEngine, RsaKey};
use tc_rsa_signer::{
    Iso9796d2Error, Iso9796d2Signer, PssSigner, PssSignerError, RsaDigestSigner,
    RsaDigestSignerError, X931Signer, X931SignerError,
};
use tc_zeroize::Zeroize;

use super::row::{
    Inner, Kind, Make, Row, digest_names, digests, invalid_params, keyed, signer_digest_name,
};
use crate::digest::{DigestEntry, RowDigest};
use crate::signer::SignerEntry;
use crate::{AlgoError, DefaultAlgoContext, ErrorKind, Params};

type Rand = fn() -> Box<dyn CryptoRng>;
type Engine = RsaBlindedEngine<RsaEngine, Box<dyn CryptoRng>>;

// The digests of PKCS#1 v1.5, those of Bouncy Castle's RsaDigestSigner, with the OID its DigestInfo
// names and the OIDs of the signature
const PKCS1: &[(&str, &str, &[&str])] = &[
    ("MD2", "1.2.840.113549.2.2", &["1.2.840.113549.1.1.2"]),
    (
        "MD4",
        "1.2.840.113549.2.4",
        &["1.2.840.113549.1.1.3", "1.3.14.3.2.2", "1.3.14.3.2.4"],
    ),
    (
        "MD5",
        "1.2.840.113549.2.5",
        &["1.2.840.113549.1.1.4", "1.3.14.3.2.3"],
    ),
    (
        "SHA-1",
        "1.3.14.3.2.26",
        &["1.2.840.113549.1.1.5", "1.3.14.3.2.29"],
    ),
    (
        "SHA-224",
        "2.16.840.1.101.3.4.2.4",
        &["1.2.840.113549.1.1.14"],
    ),
    (
        "SHA-256",
        "2.16.840.1.101.3.4.2.1",
        &["1.2.840.113549.1.1.11"],
    ),
    (
        "SHA-384",
        "2.16.840.1.101.3.4.2.2",
        &["1.2.840.113549.1.1.12"],
    ),
    (
        "SHA-512",
        "2.16.840.1.101.3.4.2.3",
        &["1.2.840.113549.1.1.13"],
    ),
    (
        "SHA-512/224",
        "2.16.840.1.101.3.4.2.5",
        &["1.2.840.113549.1.1.15"],
    ),
    (
        "SHA-512/256",
        "2.16.840.1.101.3.4.2.6",
        &["1.2.840.113549.1.1.16"],
    ),
    (
        "SHA3-224",
        "2.16.840.1.101.3.4.2.7",
        &["2.16.840.1.101.3.4.3.13"],
    ),
    (
        "SHA3-256",
        "2.16.840.1.101.3.4.2.8",
        &["2.16.840.1.101.3.4.3.14"],
    ),
    (
        "SHA3-384",
        "2.16.840.1.101.3.4.2.9",
        &["2.16.840.1.101.3.4.3.15"],
    ),
    (
        "SHA3-512",
        "2.16.840.1.101.3.4.2.10",
        &["2.16.840.1.101.3.4.3.16"],
    ),
    ("RIPEMD128", "1.3.36.3.2.2", &["1.3.36.3.3.1.3"]),
    ("RIPEMD160", "1.3.36.3.2.1", &["1.3.36.3.3.1.2"]),
    ("RIPEMD256", "1.3.36.3.2.3", &["1.3.36.3.3.1.4"]),
];

// The digests of ISO 9796-2 in Bouncy Castle's SignerUtilities
const ISO9796_2: &[&str] = &["SHA-1", "MD5", "RIPEMD160"];

// The rows of RSA signatures, to give to DefaultAlgoBuilder::reg_signer, with the names, aliases and
// OIDs of Bouncy Castle's SignerUtilities, over each digest row that is on: PKCS#1 v1.5 for the
// digests its DigestInfo names, PSS with MGF1 over the same digest and a salt of its size, X9.31 for
// the digests with a trailer, and ISO 9796-2 for SHA-1, MD5 and RIPEMD160. Further, PKCS#1 v1.5 of a
// message that is the hash itself, PSS over Bouncy Castle's default, SHA-1, and PSS of a hash. Each
// takes an RsaKey: private to sign, and public to verify. The engine is blinded, as Bouncy Castle
// builds it
pub(super) fn rsa(context: &DefaultAlgoContext) -> Vec<Box<dyn SignerEntry>> {
    let rand: Rand = context.rand();
    let mut rows: Vec<Box<dyn SignerEntry>> = vec![row(
        "NONEwithRSA".to_string(),
        ["RSA", "RSAWITHNONE", "RAWRSA"].map(String::from).to_vec(),
        &[],
        Arc::new(move |params| RawRsa::new(rsa_key(params)?, rand)),
    )];
    for digest in digests(context) {
        let base = signer_digest_name(&*digest);
        let names = digest_names(&*digest);
        let aliases = |suffixes: &[&str]| -> Vec<String> {
            names
                .iter()
                .flat_map(|name| suffixes.iter().map(move |suffix| format!("{name}{suffix}")))
                .collect()
        };

        if let Some((_, info, oids)) = PKCS1.iter().find(|(name, ..)| *name == digest.name()) {
            let (pkcs1, info) = (digest.clone(), *info);
            rows.push(row(
                format!("{base}withRSA"),
                aliases(&["WITHRSA", "WITHRSAENCRYPTION"]),
                oids,
                Arc::new(move |params| {
                    let id = AlgorithmIdentifier::with_null(info.parse().expect("a valid OID"));
                    let digest = RowDigest::new(pkcs1.clone());
                    keyed(
                        RsaDigestSigner::new(engine(rand), digest, id),
                        rsa_key(params)?,
                    )
                }),
            ));
        }
        if digest.name() != "NONE" {
            let pss = digest.clone();
            rows.push(row(
                format!("{base}withRSAandMGF1"),
                aliases(&["WITHRSAANDMGF1", "WITHRSA/PSS", "WITHRSASSA-PSS"]),
                &[],
                Arc::new(move |params| {
                    let digest = RowDigest::new(pss.clone());
                    keyed(
                        PssSigner::new(engine(rand), digest, rand()),
                        rsa_key(params)?,
                    )
                }),
            ));
        }
        if tc_rsa_signer::iso_trailers::trailer(digest.name()).is_some() {
            let x931 = digest.clone();
            rows.push(row(
                format!("{base}withRSA/X9.31"),
                aliases(&["WITHRSA/X9.31"]),
                &[],
                Arc::new(move |params| {
                    let digest = RowDigest::new(x931.clone());
                    keyed(X931Signer::new(engine(rand), digest), rsa_key(params)?)
                }),
            ));
        }
        if ISO9796_2.contains(&digest.name()) {
            let iso = digest.clone();
            rows.push(row(
                format!("{base}withRSA/ISO9796-2"),
                aliases(&["WITHRSA/ISO9796-2"]),
                &[],
                Arc::new(move |params| {
                    let digest = RowDigest::new(iso.clone());
                    keyed(
                        Iso9796d2Signer::implicit(engine(rand), digest),
                        rsa_key(params)?,
                    )
                }),
            ));
        }
        if digest.name() == "SHA-1" {
            rows.extend(sha1_pss(&digest, rand));
        }
    }
    rows
}

// PSSwithRSA, which Bouncy Castle builds over SHA-1 for the OID of RSASSA-PSS, and RAWRSASSA-PSS,
// which takes the SHA-1 hash of the message instead of the message
fn sha1_pss(digest: &Arc<dyn DigestEntry>, rand: Rand) -> [Box<dyn SignerEntry>; 2] {
    let pss = digest.clone();
    let raw = digest.clone();
    [
        row(
            "PSSwithRSA".to_string(),
            ["RSASSA-PSS", "RSAPSS"].map(String::from).to_vec(),
            &["1.2.840.113549.1.1.10"],
            Arc::new(move |params| {
                let digest = RowDigest::new(pss.clone());
                keyed(
                    PssSigner::new(engine(rand), digest, rand()),
                    rsa_key(params)?,
                )
            }),
        ),
        row(
            "RAWRSASSA-PSS".to_string(),
            ["RAWRSAPSS", "NONEWITHRSAPSS", "NONEWITHRSASSA-PSS"]
                .map(String::from)
                .to_vec(),
            &[],
            Arc::new(move |params| {
                let digest = RowDigest::new(raw.clone());
                keyed(
                    PssSigner::raw(engine(rand), digest, rand()),
                    rsa_key(params)?,
                )
            }),
        ),
    ]
}

fn row(name: String, aliases: Vec<String>, oids: &[&str], make: Make) -> Box<dyn SignerEntry> {
    Box::new(Row::new(name, aliases, oids, make))
}

fn engine(rand: Rand) -> Engine {
    RsaBlindedEngine::from_parts(RsaEngine::new(), rand())
}

fn rsa_key(params: &dyn Params) -> Result<&RsaKey, AlgoError> {
    params
        .as_any()
        .downcast_ref::<RsaKey>()
        .ok_or(AlgoError::new(ErrorKind::InvalidParams))
}

// PKCS#1 v1.5 of a message that is the hash itself, Bouncy Castle's GenericSigner over
// Pkcs1Encoding and NullDigest: the private key encrypts the message as a block of type 1, and the
// public key decrypts the signature and compares it with the message in constant time
struct RawRsa {
    encoding: Pkcs1Encoding<Engine, Box<dyn CryptoRng>>,
    private: bool,
    message: Vec<u8>,
}

impl RawRsa {
    fn new(key: &RsaKey, rand: Rand) -> Result<Box<dyn Inner>, AlgoError> {
        let private = key.is_private_key();
        let direction = if private {
            CipherDirection::Encrypt
        } else {
            CipherDirection::Decrypt
        };
        let mut encoding = Pkcs1Encoding::from_parts(engine(rand), rand());
        encoding.init(direction, key).map_err(invalid_params)?;
        Ok(Box::new(Self {
            encoding,
            private,
            message: Vec::new(),
        }))
    }
}

impl Inner for RawRsa {
    fn max_signature_size(&self) -> usize {
        if self.private {
            self.encoding.output_block_size()
        } else {
            self.encoding.input_block_size()
        }
    }

    fn update(&mut self, input: &[u8]) -> Result<(), AlgoError> {
        self.message.extend_from_slice(input);
        Ok(())
    }

    fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        if !self.private {
            return Err(AlgoError::new(ErrorKind::NotInitialized));
        }
        if output.len() < self.encoding.output_block_size() {
            return Err(AlgoError::new(ErrorKind::DataLength));
        }
        let result = self.encoding.process_block(&self.message, output);
        self.reset();
        result.map_err(|error| AlgoError::with_source(ErrorKind::DataLength, error))
    }

    fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, AlgoError> {
        if self.private {
            return Err(AlgoError::new(ErrorKind::NotInitialized));
        }
        let mut block = vec![0; self.encoding.output_block_size()];
        // A signature that does not decrypt to a block of type 1 is a wrong one
        let verified = match self.encoding.process_block(signature, &mut block) {
            Ok(written) => fixed_time_eq(&block[..written], &self.message),
            Err(_) => false,
        };
        block.zeroize();
        self.reset();
        Ok(verified)
    }

    fn reset(&mut self) {
        self.message.zeroize();
        self.message.clear();
    }
}

impl<E> Kind for RsaDigestSignerError<E> {
    fn kind(&self) -> ErrorKind {
        match self {
            RsaDigestSignerError::NotInitialized
            | RsaDigestSignerError::NotForSigning
            | RsaDigestSignerError::NotForVerifying => ErrorKind::NotInitialized,
            _ => ErrorKind::DataLength,
        }
    }
}

impl<E, C> Kind for PssSignerError<E, C> {
    fn kind(&self) -> ErrorKind {
        match self {
            PssSignerError::NotInitialized
            | PssSignerError::NotForSigning
            | PssSignerError::NotForVerifying => ErrorKind::NotInitialized,
            PssSignerError::KeyTooSmall => ErrorKind::InvalidParams,
            _ => ErrorKind::DataLength,
        }
    }
}

impl<E> Kind for X931SignerError<E> {
    fn kind(&self) -> ErrorKind {
        match self {
            X931SignerError::NotInitialized
            | X931SignerError::NotForSigning
            | X931SignerError::NotForVerifying => ErrorKind::NotInitialized,
            X931SignerError::NoTrailer | X931SignerError::KeyTooSmall => ErrorKind::InvalidParams,
            _ => ErrorKind::DataLength,
        }
    }
}

impl<E> Kind for Iso9796d2Error<E> {
    fn kind(&self) -> ErrorKind {
        match self {
            Iso9796d2Error::NotInitialized
            | Iso9796d2Error::NotForSigning
            | Iso9796d2Error::NotForVerifying => ErrorKind::NotInitialized,
            Iso9796d2Error::NoTrailer | Iso9796d2Error::KeyTooSmall => ErrorKind::InvalidParams,
            Iso9796d2Error::Cipher(_) => ErrorKind::DataLength,
            _ => ErrorKind::InvalidCiphertext,
        }
    }
}

#[cfg(all(test, feature = "sha"))]
mod tests {
    use std::sync::OnceLock;

    use tc_asn1_x509::alg::AlgorithmIdentifier;
    use tc_rsa::{RsaEngine, RsaKey};
    use tc_rsa_signer::RsaDigestSigner;
    use tc_sha::Sha256Digest;
    use tc_signer::{Signer as _, SignerInit};

    use crate::params::{generate::KeyLength, generate::RsaKeyGenParams};
    use crate::signer::Signer;
    use crate::{Algo, AlgoBuilder, DefaultAlgoBuilder, ErrorKind};

    const NAME: &str = "SHA-256withRSA";

    fn oid(dotted: &str) -> tc_asn1::Asn1Oid {
        dotted.parse().unwrap()
    }
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

    fn signer(key: &RsaKey) -> Box<dyn Signer> {
        let mut signer = algo().signer().get_by_name(NAME).unwrap();
        signer.init(key).unwrap();
        signer
    }

    fn signature() -> Vec<u8> {
        let mut signer = signer(&keys().1);
        signer.update(MESSAGE).unwrap();
        signer.sign().unwrap()
    }

    #[test]
    fn a_signature_verifies_under_the_public_key() {
        let signature = signature();
        assert_eq!(signature.len(), 128);

        let mut verifier = signer(&keys().0);
        verifier.update(MESSAGE).unwrap();
        assert!(verifier.verify_signature(&signature).unwrap());
    }

    #[test]
    fn a_changed_message_or_signature_is_ok_false() {
        let signature = signature();

        let mut verifier = signer(&keys().0);
        verifier.update(b"attack at dusk").unwrap();
        assert!(!verifier.verify_signature(&signature).unwrap());

        let mut changed = signature;
        changed[127] ^= 1;
        verifier.update(MESSAGE).unwrap();
        assert!(!verifier.verify_signature(&changed).unwrap());
    }

    #[test]
    fn the_row_signs_as_pkcs1_over_sha256_says() {
        let (public, private) = keys();
        let digest_id = || AlgorithmIdentifier::with_null(oid("2.16.840.1.101.3.4.2.1"));

        // What the row signs, the crate underneath verifies
        let mut plain = RsaDigestSigner::new(RsaEngine::new(), Sha256Digest::new(), digest_id());
        plain.init(public).unwrap();
        plain.update(MESSAGE).unwrap();
        assert!(plain.verify_signature(&signature()).unwrap());

        // PKCS#1 v1.5 is deterministic, so it signs the same bytes
        let mut plain = RsaDigestSigner::new(RsaEngine::new(), Sha256Digest::new(), digest_id());
        plain.init(private).unwrap();
        plain.update(MESSAGE).unwrap();
        let mut output = [0; 128];
        let written = plain.generate_signature(&mut output).unwrap();
        assert_eq!(output[..written], signature());
    }

    #[test]
    fn the_row_is_found_by_its_aliases_and_oid() {
        let algo = algo();
        for name in [
            "sha256withrsa",
            "SHA256WITHRSAENCRYPTION",
            "SHA-256withRSAEncryption",
        ] {
            assert!(algo.signer().get_by_name(name).is_ok(), "{name}");
        }
        assert!(
            algo.signer()
                .get_by_oid(&oid("1.2.840.113549.1.1.11"))
                .is_ok()
        );
    }

    #[test]
    fn init_refuses_params_of_another_type() {
        let mut signer = algo().signer().get_by_name(NAME).unwrap();
        let error = signer.init(&KeyLength::new(1)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }

    #[test]
    fn the_calls_report_a_signer_that_was_not_initialized() {
        let mut signer = algo().signer().get_by_name(NAME).unwrap();
        let error = signer.update(MESSAGE).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
        let error = signer.generate_signature(&mut [0; 128]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
        let error = signer.verify_signature(&[0; 128]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
    }

    #[test]
    fn a_public_key_only_verifies_and_a_private_key_only_signs() {
        let (public, private) = keys();

        let mut verifier = signer(public);
        let error = verifier.generate_signature(&mut [0; 128]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);

        let mut signing = signer(private);
        let error = signing.verify_signature(&[0; 128]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
    }

    #[test]
    fn an_output_too_short_is_data_length() {
        let mut signer = signer(&keys().1);
        signer.update(MESSAGE).unwrap();
        let error = signer.generate_signature(&mut [0; 16]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DataLength);
    }

    #[test]
    fn signing_starts_the_next_message_and_reset_discards_the_message() {
        let mut signer = signer(&keys().1);
        signer.update(MESSAGE).unwrap();
        let first = signer.sign().unwrap();

        signer.update(MESSAGE).unwrap();
        assert_eq!(signer.sign().unwrap(), first);

        signer.update(b"other").unwrap();
        signer.reset();
        signer.update(MESSAGE).unwrap();
        assert_eq!(signer.sign().unwrap(), first);
    }
}

#[cfg(all(test, feature = "sha", feature = "md", feature = "ripemd"))]
mod family_tests {
    use std::sync::OnceLock;

    use tc_rsa::RsaKey;

    use crate::params::generate::RsaKeyGenParams;
    use crate::{Algo, AlgoBuilder, DefaultAlgoBuilder, ErrorKind, Params};

    const MESSAGE: &[u8] = b"attack at dawn";

    fn algo() -> Box<dyn Algo> {
        DefaultAlgoBuilder::default().build()
    }

    // 2048 bits, as large a key as is quick to generate; PSS over a digest of more than 127 bytes
    // needs a larger one, which the test below checks is refused
    fn keys() -> &'static (RsaKey, RsaKey) {
        static KEYS: OnceLock<(RsaKey, RsaKey)> = OnceLock::new();
        KEYS.get_or_init(|| {
            let pair = algo()
                .key_pair_generator()
                .generate_by_name_with("RSA", &RsaKeyGenParams::new(2048))
                .unwrap();
            let key =
                |params: &dyn Params| params.as_any().downcast_ref::<RsaKey>().unwrap().clone();
            (key(pair.public()), key(pair.private()))
        })
    }

    fn sign(name: &str, message: &[u8]) -> Vec<u8> {
        let mut signer = algo().signer().get_by_name(name).unwrap();
        signer.init(&keys().1).unwrap();
        signer.update(message).unwrap();
        signer.sign().unwrap()
    }

    fn verify(name: &str, message: &[u8], signature: &[u8]) -> bool {
        let mut verifier = algo().signer().get_by_name(name).unwrap();
        verifier.init(&keys().0).unwrap();
        verifier.update(message).unwrap();
        verifier.verify_signature(signature).unwrap()
    }

    #[test]
    fn every_rsa_row_verifies_what_it_signs_and_refuses_another_message() {
        let names: Vec<String> = algo()
            .signer()
            .algorithms()
            .map(|entry| entry.name().to_string())
            .filter(|name| name.contains("RSA"))
            .filter(|name| name != "RAWRSASSA-PSS")
            .collect();
        assert!(names.len() >= 15, "{names:?}");
        for name in &names {
            // PSS needs two hashes and two bytes more than the 256 of the key, so a hash of
            // 128 bytes, as SKEIN-1024-1024 gives, is too long for it
            if name.starts_with("SKEIN-1024-1024with") && name.ends_with("andMGF1") {
                let mut signer = algo().signer().get_by_name(name).unwrap();
                let error = signer.init(&keys().1).unwrap_err();
                assert_eq!(error.kind(), ErrorKind::InvalidParams, "{name}");
                continue;
            }
            let message: &[u8] = if name == "NONEwithRSA" {
                &[7; 32]
            } else {
                MESSAGE
            };
            let signature = sign(name, message);
            assert!(verify(name, message, &signature), "{name}");
            let mut other = message.to_vec();
            other[0] ^= 1;
            assert!(!verify(name, &other, &signature), "{name}");
        }
    }

    // NONEwithRSA signs what it is given, so the DigestInfo of SHA-256 and the hash give the
    // signature of SHA-256withRSA, which PKCS#1 v1.5 makes the same each time
    #[test]
    fn none_with_rsa_over_a_digest_info_is_sha256_with_rsa() {
        let mut digest = algo().digest().get_by_name("SHA-256").unwrap();
        digest.try_update(MESSAGE).unwrap();
        let mut info = vec![
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ];
        info.extend(digest.finalize().unwrap());

        let signature = sign("SHA-256withRSA", MESSAGE);
        assert_eq!(sign("RAWRSA", &info), signature);
        assert!(verify("NONEwithRSA", &info, &signature));
    }

    // RAWRSASSA-PSS takes the SHA-1 hash of the message, and PSSwithRSA the message
    #[test]
    fn raw_pss_of_the_hash_verifies_as_pss_of_the_message() {
        let mut digest = algo().digest().get_by_name("SHA-1").unwrap();
        digest.try_update(MESSAGE).unwrap();
        let hash = digest.finalize().unwrap();

        let signature = sign("RAWRSASSA-PSS", &hash);
        assert!(verify("PSSwithRSA", MESSAGE, &signature));
        assert!(verify("SHA-1withRSAandMGF1", MESSAGE, &signature));
        assert!(verify("NONEWITHRSAPSS", &hash, &signature));
    }

    #[test]
    fn the_rows_are_found_by_the_names_and_oids_of_bouncy_castle() {
        let algo = algo();
        let signers = algo.signer();
        for (name, canonical) in [
            ("SHA256WITHRSA/PSS", "SHA-256withRSAandMGF1"),
            ("SHA-256WITHRSASSA-PSS", "SHA-256withRSAandMGF1"),
            ("RSASSA-PSS", "PSSwithRSA"),
            ("RSA", "NONEwithRSA"),
            ("SHA1WITHRSA/ISO9796-2", "SHA-1withRSA/ISO9796-2"),
            ("RIPEMD160withRSA/ISO9796-2", "RIPEMD160withRSA/ISO9796-2"),
            ("SHA256WITHRSA/X9.31", "SHA-256withRSA/X9.31"),
            ("MD5WITHRSAENCRYPTION", "MD5withRSA"),
        ] {
            let entry = signers
                .algorithms()
                .find(|entry| {
                    entry.name().eq_ignore_ascii_case(name)
                        || entry
                            .aliases()
                            .iter()
                            .any(|alias| alias.eq_ignore_ascii_case(name))
                })
                .unwrap_or_else(|| panic!("{name}"));
            assert_eq!(entry.name(), canonical, "{name}");
        }
        for (oid, canonical) in [
            ("1.2.840.113549.1.1.10", "PSSwithRSA"),
            ("1.3.14.3.2.3", "MD5withRSA"),
            ("1.3.14.3.2.29", "SHA-1withRSA"),
            ("1.3.36.3.3.1.2", "RIPEMD160withRSA"),
        ] {
            let oid = oid.parse().unwrap();
            let entry = signers
                .algorithms()
                .find(|entry| entry.oids().contains(&oid))
                .unwrap_or_else(|| panic!("{oid}"));
            assert_eq!(entry.name(), canonical);
            assert!(signers.get_by_oid(&oid).is_ok());
        }
    }

    #[test]
    fn a_public_key_cannot_sign_with_none_with_rsa() {
        let mut signer = algo().signer().get_by_name("NONEwithRSA").unwrap();
        signer.init(&keys().0).unwrap();
        signer.update(&[1; 20]).unwrap();
        let error = signer.sign().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
    }
}
