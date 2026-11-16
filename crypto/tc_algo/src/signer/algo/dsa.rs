use tc_dsa::DsaDigestSigner;
use tc_dsa_key::{DsaPrivateKey, DsaPublicKey};
use tc_dsa_signer::DsaSigner;

use super::digest_dsa::{Rand, Spec, k, row};
use super::row::{Inner, digests, keyed};
use crate::digest::RowDigest;
use crate::signer::SignerEntry;
use crate::{AlgoError, DefaultAlgoContext, Params};

// The OIDs of Bouncy Castle's SignerUtilities, by the name of the row
const OIDS: &[(&str, &[&str])] = &[
    ("SHA-1withDSA", &["1.2.840.10040.4.3", "1.3.14.3.2.27"]),
    ("SHA-224withDSA", &["2.16.840.1.101.3.4.3.1"]),
    ("SHA-256withDSA", &["2.16.840.1.101.3.4.3.2"]),
    ("SHA-384withDSA", &["2.16.840.1.101.3.4.3.3"]),
    ("SHA-512withDSA", &["2.16.840.1.101.3.4.3.4"]),
    ("SHA3-224withDSA", &["2.16.840.1.101.3.4.3.5"]),
    ("SHA3-256withDSA", &["2.16.840.1.101.3.4.3.6"]),
    ("SHA3-384withDSA", &["2.16.840.1.101.3.4.3.7"]),
    ("SHA3-512withDSA", &["2.16.840.1.101.3.4.3.8"]),
];

// The rows of DSA, FIPS 186, to give to DefaultAlgoBuilder::reg_signer, over each digest row that is
// on, with the names, aliases and OIDs of Bouncy Castle's SignerUtilities, where DSA alone is
// SHA-1withDSA and RAWDSA is NONEwithDSA. Each takes a DsaPrivateKey to sign and a DsaPublicKey to
// verify, gives the signature in DER, and draws k at random
pub(super) fn dsa(context: &DefaultAlgoContext) -> Vec<Box<dyn SignerEntry>> {
    let rand: Rand = context.rand();
    digests(context)
        .iter()
        .map(|digest| {
            row(
                digest,
                "DSA",
                &[on],
                OIDS,
                &[("SHA-1", "DSA"), ("NONE", "RAWDSA")],
                rand,
            )
        })
        .collect()
}

fn on(params: &dyn Params, spec: &Spec) -> Option<Result<Box<dyn Inner>, AlgoError>> {
    let signer =
        || DsaDigestSigner::new(DsaSigner::new(k(spec)), RowDigest::new(spec.digest.clone()));
    let params = params.as_any();
    if let Some(key) = params.downcast_ref::<DsaPrivateKey>() {
        return Some(keyed(signer(), key));
    }
    let key = params.downcast_ref::<DsaPublicKey>()?;
    Some(keyed(signer(), key))
}

#[cfg(all(test, feature = "sha1", feature = "sha256"))]
mod tests {
    use std::sync::OnceLock;

    use crate::generate::KeyPair;
    use crate::params::{DsaKeyGenParams, DsaPublicKey};
    use crate::{Algo, AlgoBuilder, DefaultAlgoBuilder, ErrorKind};

    const MESSAGE: &[u8] = b"attack at dawn";

    fn algo() -> Box<dyn Algo> {
        DefaultAlgoBuilder::default().build()
    }

    // One pair for all the tests, since generating the domain is slow
    fn pair() -> &'static KeyPair {
        static PAIR: OnceLock<KeyPair> = OnceLock::new();
        PAIR.get_or_init(|| {
            algo()
                .key_pair_generator()
                .generate_by_name_with("DSA", &DsaKeyGenParams::new(1024, 160))
                .unwrap()
        })
    }

    fn sign(name: &str) -> Vec<u8> {
        let mut signer = algo().signer().get_by_name(name).unwrap();
        signer.init(pair().private()).unwrap();
        signer.update(MESSAGE).unwrap();
        signer.sign().unwrap()
    }

    fn verify(name: &str, message: &[u8], signature: &[u8]) -> bool {
        let mut verifier = algo().signer().get_by_name(name).unwrap();
        verifier.init(pair().public()).unwrap();
        verifier.update(message).unwrap();
        verifier.verify_signature(signature).unwrap()
    }

    #[test]
    fn dsa_verifies_what_it_signs_by_its_names_and_oids() {
        for name in ["SHA-256withDSA", "DSA", "SHA256/DSA", "DSAWITHSHA-256"] {
            let signature = sign(name);
            assert_eq!(signature[0], 0x30, "{name}");
            assert!(verify(name, MESSAGE, &signature), "{name}");
            assert!(!verify(name, b"attack at dusk", &signature), "{name}");
        }
        let algo = algo();
        for oid in [
            "1.2.840.10040.4.3",
            "1.3.14.3.2.27",
            "2.16.840.1.101.3.4.3.2",
        ] {
            assert!(
                algo.signer().get_by_oid(&oid.parse().unwrap()).is_ok(),
                "{oid}"
            );
        }
    }

    // The domain of a key generates more keys over it, which sign and verify alike
    #[test]
    fn the_domain_of_a_key_generates_keys_over_it() {
        let domain = pair()
            .public()
            .as_any()
            .downcast_ref::<DsaPublicKey>()
            .unwrap()
            .params()
            .clone();
        let other = algo()
            .key_pair_generator()
            .generate_by_name_with("DSA", &domain)
            .unwrap();
        let mut signer = algo().signer().get_by_name("SHA-1withDSA").unwrap();
        signer.init(other.private()).unwrap();
        signer.update(MESSAGE).unwrap();
        let signature = signer.sign().unwrap();
        let mut verifier = algo().signer().get_by_name("SHA-1withDSA").unwrap();
        verifier.init(other.public()).unwrap();
        verifier.update(MESSAGE).unwrap();
        assert!(verifier.verify_signature(&signature).unwrap());
        // A key of the other pair does not verify it
        assert!(!verify("SHA-1withDSA", MESSAGE, &signature));
    }

    #[test]
    fn dsa_needs_init_and_refuses_another_size() {
        let algo = algo();
        let generators = algo.key_pair_generator();
        let error = generators.generate_by_name("DSA").err().unwrap();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
        let error = generators
            .generate_by_name_with("DSA", &DsaKeyGenParams::new(1000, 160))
            .err()
            .unwrap();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}
