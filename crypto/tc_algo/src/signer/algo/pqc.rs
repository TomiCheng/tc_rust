use std::sync::Arc;

use rand_core::CryptoRng;
use tc_signer::SignerInit;

use super::row::{Inner, Kind, Row, keyed};
use crate::signer::SignerEntry;
use crate::{AlgoError, DefaultAlgoContext, ErrorKind, Params};

type Rand = fn() -> Box<dyn CryptoRng>;

// The rows of ML-DSA, FIPS 204, and SLH-DSA, FIPS 205, to give to DefaultAlgoBuilder::reg_signer,
// with the names and OIDs of Bouncy Castle's SignerUtilities: each parameter set, pure and with its
// pre-hash, hedged with fresh randomness and an empty context, as Bouncy Castle builds them. Each
// takes the private key to sign and the public key to verify, of the ML-DSA or SLH-DSA key pair
// generator, over the row's parameter set
pub(super) fn pqc(context: &DefaultAlgoContext) -> Vec<Box<dyn SignerEntry>> {
    #[allow(unused_variables, reason = "unused when neither family is on")]
    let rand: Rand = context.rand();
    #[allow(unused_mut, reason = "empty when neither family is on")]
    let mut rows: Vec<Box<dyn SignerEntry>> = Vec::new();

    #[cfg(feature = "ml-dsa")]
    {
        use tc_ml_dsa::{
            HashMlDsaSigner, MlDsaParameters, MlDsaPrivateKey, MlDsaPublicKey, MlDsaSigner,
        };
        type Keys = (MlDsaPrivateKey, MlDsaPublicKey);
        const SETS: [(MlDsaParameters, &str, &str); 3] = [
            (
                MlDsaParameters::ML_DSA_44,
                "2.16.840.1.101.3.4.3.17",
                "2.16.840.1.101.3.4.3.32",
            ),
            (
                MlDsaParameters::ML_DSA_65,
                "2.16.840.1.101.3.4.3.18",
                "2.16.840.1.101.3.4.3.33",
            ),
            (
                MlDsaParameters::ML_DSA_87,
                "2.16.840.1.101.3.4.3.19",
                "2.16.840.1.101.3.4.3.34",
            ),
        ];
        for (set, pure, hash) in SETS {
            rows.push(row(
                set.name().to_uppercase(),
                &[pure],
                Arc::new(move |params| either::<Keys, _, _>(params, MlDsaSigner::new(set, rand()))),
            ));
            rows.push(row(
                format!("{}-WITH-SHA512", set.name().to_uppercase()),
                &[hash],
                Arc::new(move |params| {
                    either::<Keys, _, _>(params, HashMlDsaSigner::new(set, rand()))
                }),
            ));
        }
    }

    #[cfg(feature = "slh-dsa")]
    {
        use tc_slh_dsa::{
            HashSlhDsaSigner, SlhDsaParameters, SlhDsaPrivateKey, SlhDsaPublicKey, SlhDsaSigner,
        };
        type Keys = (SlhDsaPrivateKey, SlhDsaPublicKey);
        // Each set, its OID, the digest of its pre-hash, and the OID with it
        const SETS: [(SlhDsaParameters, &str, &str, &str); 12] = [
            (
                SlhDsaParameters::SHA2_128S,
                "2.16.840.1.101.3.4.3.20",
                "SHA256",
                "2.16.840.1.101.3.4.3.35",
            ),
            (
                SlhDsaParameters::SHA2_128F,
                "2.16.840.1.101.3.4.3.21",
                "SHA256",
                "2.16.840.1.101.3.4.3.36",
            ),
            (
                SlhDsaParameters::SHA2_192S,
                "2.16.840.1.101.3.4.3.22",
                "SHA512",
                "2.16.840.1.101.3.4.3.37",
            ),
            (
                SlhDsaParameters::SHA2_192F,
                "2.16.840.1.101.3.4.3.23",
                "SHA512",
                "2.16.840.1.101.3.4.3.38",
            ),
            (
                SlhDsaParameters::SHA2_256S,
                "2.16.840.1.101.3.4.3.24",
                "SHA512",
                "2.16.840.1.101.3.4.3.39",
            ),
            (
                SlhDsaParameters::SHA2_256F,
                "2.16.840.1.101.3.4.3.25",
                "SHA512",
                "2.16.840.1.101.3.4.3.40",
            ),
            (
                SlhDsaParameters::SHAKE_128S,
                "2.16.840.1.101.3.4.3.26",
                "SHAKE128",
                "2.16.840.1.101.3.4.3.41",
            ),
            (
                SlhDsaParameters::SHAKE_128F,
                "2.16.840.1.101.3.4.3.27",
                "SHAKE128",
                "2.16.840.1.101.3.4.3.42",
            ),
            (
                SlhDsaParameters::SHAKE_192S,
                "2.16.840.1.101.3.4.3.28",
                "SHAKE256",
                "2.16.840.1.101.3.4.3.43",
            ),
            (
                SlhDsaParameters::SHAKE_192F,
                "2.16.840.1.101.3.4.3.29",
                "SHAKE256",
                "2.16.840.1.101.3.4.3.44",
            ),
            (
                SlhDsaParameters::SHAKE_256S,
                "2.16.840.1.101.3.4.3.30",
                "SHAKE256",
                "2.16.840.1.101.3.4.3.45",
            ),
            (
                SlhDsaParameters::SHAKE_256F,
                "2.16.840.1.101.3.4.3.31",
                "SHAKE256",
                "2.16.840.1.101.3.4.3.46",
            ),
        ];
        for (set, pure, digest, hash) in SETS {
            rows.push(row(
                set.name().to_uppercase(),
                &[pure],
                Arc::new(move |params| {
                    either::<Keys, _, _>(params, SlhDsaSigner::new(set, rand()))
                }),
            ));
            rows.push(row(
                format!("{}-WITH-{digest}", set.name().to_uppercase()),
                &[hash],
                Arc::new(move |params| {
                    either::<Keys, _, _>(params, HashSlhDsaSigner::new(set, rand()))
                }),
            ));
        }
    }

    rows
}

fn row(name: String, oids: &[&str], make: super::row::Make) -> Box<dyn SignerEntry> {
    Box::new(Row::new(name, Vec::new(), oids, make))
}

// The signer keyed by the private key K.0 to sign, or the public key K.1 to verify
fn either<K, S, E>(params: &dyn Params, signer: S) -> Result<Box<dyn Inner>, AlgoError>
where
    K: Pair,
    S: SignerInit<K::Private, Error = E> + SignerInit<K::Public, Error = E> + Inner + 'static,
    E: core::error::Error + Send + Sync + 'static,
{
    let params = params.as_any();
    if let Some(key) = params.downcast_ref::<K::Private>() {
        return keyed(signer, key);
    }
    let key = params
        .downcast_ref::<K::Public>()
        .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
    keyed(signer, key)
}

trait Pair {
    type Private: 'static;
    type Public: 'static;
}

impl<A: 'static, B: 'static> Pair for (A, B) {
    type Private = A;
    type Public = B;
}

#[cfg(feature = "ml-dsa")]
impl Kind for tc_ml_dsa::MlDsaError {
    fn kind(&self) -> ErrorKind {
        use tc_ml_dsa::MlDsaError as E;
        match self {
            E::NotInitialized | E::NotForSigning | E::NotForVerification => {
                ErrorKind::NotInitialized
            }
            E::OutputTooShort => ErrorKind::DataLength,
            _ => ErrorKind::InvalidParams,
        }
    }
}

#[cfg(feature = "slh-dsa")]
impl Kind for tc_slh_dsa::SlhDsaError {
    fn kind(&self) -> ErrorKind {
        use tc_slh_dsa::SlhDsaError as E;
        match self {
            E::NotInitialized | E::NotForSigning | E::NotForVerification => {
                ErrorKind::NotInitialized
            }
            E::OutputTooShort => ErrorKind::DataLength,
            _ => ErrorKind::InvalidParams,
        }
    }
}

#[cfg(all(test, feature = "ml-dsa", feature = "slh-dsa"))]
mod tests {
    use crate::generate::KeyPair;
    use crate::params::{key::ml_dsa::MlDsaParameters, key::slh_dsa::SlhDsaParameters};
    use crate::{Algo, AlgoBuilder, DefaultAlgoBuilder, ErrorKind, Params};

    fn algo() -> Box<dyn Algo> {
        DefaultAlgoBuilder::default().build()
    }

    fn round_trip(name: &str, pair: &KeyPair) {
        let mut signer = algo().signer().get_by_name(name).unwrap();
        signer.init(pair.private()).unwrap();
        signer.update(b"attack at dawn").unwrap();
        let signature = signer.sign().unwrap();

        let mut verifier = algo().signer().get_by_name(name).unwrap();
        verifier.init(pair.public()).unwrap();
        verifier.update(b"attack at dawn").unwrap();
        assert!(verifier.verify_signature(&signature).unwrap(), "{name}");
        verifier.update(b"attack at dusk").unwrap();
        assert!(!verifier.verify_signature(&signature).unwrap(), "{name}");
    }

    fn pair(generator: &str, set: &dyn Params) -> KeyPair {
        algo()
            .key_pair_generator()
            .generate_by_name_with(generator, set)
            .unwrap()
    }

    #[test]
    fn ml_dsa_signs_pure_and_with_its_pre_hash() {
        let pair = pair("ML-DSA", &MlDsaParameters::ML_DSA_44);
        round_trip("ML-DSA-44", &pair);
        round_trip("ml-dsa-44-with-sha512", &pair);
        let oid = "2.16.840.1.101.3.4.3.17".parse().unwrap();
        assert!(algo().signer().get_by_oid(&oid).is_ok());

        // A key of another parameter set
        let mut signer = algo().signer().get_by_name("ML-DSA-65").unwrap();
        let error = signer.init(pair.private()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }

    #[test]
    fn slh_dsa_signs_pure_and_with_its_pre_hash() {
        let pair = pair("SLH-DSA", &SlhDsaParameters::SHAKE_128F);
        round_trip("SLH-DSA-SHAKE-128F", &pair);
        round_trip("SLH-DSA-SHAKE-128F-WITH-SHAKE128", &pair);
        let oid = "2.16.840.1.101.3.4.3.27".parse().unwrap();
        assert!(algo().signer().get_by_oid(&oid).is_ok());
    }

    #[test]
    fn the_generators_need_a_parameter_set() {
        let algo = algo();
        let generators = algo.key_pair_generator();
        for name in ["ML-DSA", "SLH-DSA"] {
            let error = generators.generate_by_name(name).err().unwrap();
            assert_eq!(error.kind(), ErrorKind::NotInitialized, "{name}");
        }
    }
}
