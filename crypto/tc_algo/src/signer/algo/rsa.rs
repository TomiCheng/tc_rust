use rand_core::CryptoRng;
use tc_asn1::Asn1Oid;
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_rsa::{RsaBlindedEngine, RsaEngine, RsaError, RsaKey};
use tc_rsa_signer::{RsaDigestSigner, RsaDigestSignerError};
use tc_sha::Sha256Digest;
use tc_signer::{Signer as _, SignerInit};

use crate::signer::{Signer, SignerEntry};
use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind, Params};

// The row of RSA signatures with PKCS#1 v1.5, to give to DefaultAlgoBuilder::reg_signer. Its names
// and OID are those of Bouncy Castle's SignerUtilities
pub(super) fn rsa(context: &DefaultAlgoContext) -> Vec<Box<dyn SignerEntry>> {
    vec![Box::new(Row {
        aliases: [
            "SHA256WITHRSA",
            "SHA256WITHRSAENCRYPTION",
            "SHA-256WITHRSAENCRYPTION",
        ]
        .map(String::from)
        .to_vec(),
        oids: vec![oid("1.2.840.113549.1.1.11")],
        rand: context.rand(),
    })]
}

fn oid(dotted: &str) -> Asn1Oid {
    dotted.parse().expect("a valid OID")
}

struct Row {
    aliases: Vec<String>,
    oids: Vec<Asn1Oid>,
    rand: fn() -> Box<dyn CryptoRng>,
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        "SHA-256withRSA"
    }

    fn aliases(&self) -> &[String] {
        &self.aliases
    }

    fn oids(&self) -> &[Asn1Oid] {
        &self.oids
    }
}

impl SignerEntry for Row {
    fn create(&self) -> Box<dyn Signer> {
        // Blinded, as Bouncy Castle's SignerUtilities builds it. The DigestInfo names id-sha256,
        // with NULL parameters
        Box::new(Rsa(RsaDigestSigner::new(
            RsaBlindedEngine::from_parts(RsaEngine::new(), (self.rand)()),
            Sha256Digest::new(),
            AlgorithmIdentifier::with_null(oid("2.16.840.1.101.3.4.2.1")),
        )))
    }
}

// Its params are an RsaKey: private to sign, and public to verify
struct Rsa(RsaDigestSigner<RsaBlindedEngine<RsaEngine, Box<dyn CryptoRng>>, Sha256Digest>);

impl Signer for Rsa {
    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError> {
        let key = params
            .as_any()
            .downcast_ref::<RsaKey>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        self.0
            .init(key)
            .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))
    }

    fn max_signature_size(&self) -> usize {
        self.0.max_signature_size()
    }

    fn update(&mut self, input: &[u8]) -> Result<(), AlgoError> {
        self.0.update(input).map_err(algo_error)
    }

    fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        self.0.generate_signature(output).map_err(algo_error)
    }

    fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, AlgoError> {
        self.0.verify_signature(signature).map_err(algo_error)
    }

    fn reset(&mut self) {
        self.0.reset();
    }
}

fn algo_error(error: RsaDigestSignerError<RsaError>) -> AlgoError {
    let kind = match error {
        RsaDigestSignerError::NotInitialized
        | RsaDigestSignerError::NotForSigning
        | RsaDigestSignerError::NotForVerifying => ErrorKind::NotInitialized,
        _ => ErrorKind::DataLength,
    };
    AlgoError::with_source(kind, error)
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use tc_asn1_x509::alg::AlgorithmIdentifier;
    use tc_rsa::{RsaEngine, RsaKey};
    use tc_rsa_signer::RsaDigestSigner;
    use tc_sha::Sha256Digest;
    use tc_signer::{Signer as _, SignerInit};

    use super::oid;
    use crate::params::{KeyLength, RsaKeyGenParams};
    use crate::signer::Signer;
    use crate::{Algo, AlgoBuilder, DefaultAlgoBuilder, ErrorKind};

    const NAME: &str = "SHA-256withRSA";
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
