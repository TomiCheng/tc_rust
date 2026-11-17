#[cfg(feature = "ecgost3410")]
use std::sync::Arc;

use tc_bigint::PaddedBigUint;
#[cfg(any(feature = "ecdsa", feature = "ecnr"))]
use tc_dsa::DsaDigestSigner;
use tc_ec_core::Curve;
use tc_ec_key::{EcPrivateKey, EcPublicKey};

#[cfg(any(feature = "ecdsa", feature = "ecnr"))]
use super::digest_dsa::{Spec, k, row};
#[cfg(feature = "ecgost3410")]
use super::row::Row;
#[cfg(any(feature = "ecdsa", feature = "ecnr"))]
use super::row::digests;
use super::row::{Inner, keyed};
#[cfg(feature = "ecgost3410")]
use crate::ErrorKind;
#[cfg(any(feature = "ecdsa", feature = "ecnr"))]
use crate::digest::RowDigest;
use crate::signer::SignerEntry;
use crate::{AlgoError, DefaultAlgoContext, Params};

type Rand = fn() -> Box<dyn rand_core::CryptoRng>;

use crate::params::ec_curves::ct_curves as curves;

// The OIDs of Bouncy Castle's SignerUtilities, by the name of the row
#[cfg(feature = "ecdsa")]
const ECDSA_OIDS: &[(&str, &[&str])] = &[
    ("SHA-1withECDSA", &["1.2.840.10045.4.1", "1.3.36.3.3.2.1"]),
    ("SHA-224withECDSA", &["1.2.840.10045.4.3.1"]),
    ("SHA-256withECDSA", &["1.2.840.10045.4.3.2"]),
    ("SHA-384withECDSA", &["1.2.840.10045.4.3.3"]),
    ("SHA-512withECDSA", &["1.2.840.10045.4.3.4"]),
    ("RIPEMD160withECDSA", &["1.3.36.3.3.2.2"]),
    ("SHA3-224withECDSA", &["2.16.840.1.101.3.4.3.9"]),
    ("SHA3-256withECDSA", &["2.16.840.1.101.3.4.3.10"]),
    ("SHA3-384withECDSA", &["2.16.840.1.101.3.4.3.11"]),
    ("SHA3-512withECDSA", &["2.16.840.1.101.3.4.3.12"]),
    ("SHA-1withPLAIN-ECDSA", &["0.4.0.127.0.7.1.1.4.1.1"]),
    ("SHA-224withPLAIN-ECDSA", &["0.4.0.127.0.7.1.1.4.1.2"]),
    ("SHA-256withPLAIN-ECDSA", &["0.4.0.127.0.7.1.1.4.1.3"]),
    ("SHA-384withPLAIN-ECDSA", &["0.4.0.127.0.7.1.1.4.1.4"]),
    ("SHA-512withPLAIN-ECDSA", &["0.4.0.127.0.7.1.1.4.1.5"]),
    ("RIPEMD160withPLAIN-ECDSA", &["0.4.0.127.0.7.1.1.4.1.6"]),
    ("SHA3-224withPLAIN-ECDSA", &["0.4.0.127.0.7.1.1.4.1.8"]),
    ("SHA3-256withPLAIN-ECDSA", &["0.4.0.127.0.7.1.1.4.1.9"]),
    ("SHA3-384withPLAIN-ECDSA", &["0.4.0.127.0.7.1.1.4.1.10"]),
    ("SHA3-512withPLAIN-ECDSA", &["0.4.0.127.0.7.1.1.4.1.11"]),
    ("SHA-1withCVC-ECDSA", &["0.4.0.127.0.7.2.2.2.2.1"]),
    ("SHA-224withCVC-ECDSA", &["0.4.0.127.0.7.2.2.2.2.2"]),
    ("SHA-256withCVC-ECDSA", &["0.4.0.127.0.7.2.2.2.2.3"]),
    ("SHA-384withCVC-ECDSA", &["0.4.0.127.0.7.2.2.2.2.4"]),
    ("SHA-512withCVC-ECDSA", &["0.4.0.127.0.7.2.2.2.2.5"]),
];

// The rows of the signatures over EC keys, to give to DefaultAlgoBuilder::reg_signer, with the
// names, aliases and OIDs of Bouncy Castle's SignerUtilities. Over each digest row that is on:
// ECDSA, with its signature in DER; PLAIN-ECDSA and CVC-ECDSA, ECDSA with r and s side by side; and
// ECNR. NONE signs a message that is the hash itself. And GOST R 34.10-2001 and -2012 over their
// GOST R 34.11 digests. Each takes an EcPrivateKey to sign and an EcPublicKey to verify, on any
// curve of the EC key pair generator, and draws k at random, as Bouncy Castle does
pub(super) fn ec(context: &DefaultAlgoContext) -> Vec<Box<dyn SignerEntry>> {
    #[allow(unused_variables, reason = "ECGOST 3410 alone draws no digest row")]
    let rand: Rand = context.rand();
    #[allow(unused_mut, reason = "empty when no scheme is on")]
    let mut rows: Vec<Box<dyn SignerEntry>> = Vec::new();
    #[cfg(any(feature = "ecdsa", feature = "ecnr"))]
    for digest in digests(context) {
        #[cfg(feature = "ecdsa")]
        {
            let extra = &[("SHA-1", "ECDSA")];
            rows.push(row(
                &digest,
                "ECDSA",
                curves!(ecdsa),
                ECDSA_OIDS,
                extra,
                rand,
            ));
            rows.push(row(
                &digest,
                "PLAIN-ECDSA",
                curves!(plain_ecdsa),
                ECDSA_OIDS,
                &[],
                rand,
            ));
            rows.push(row(
                &digest,
                "CVC-ECDSA",
                curves!(plain_ecdsa),
                ECDSA_OIDS,
                &[],
                rand,
            ));
        }
        #[cfg(feature = "ecnr")]
        rows.push(row(&digest, "ECNR", curves!(ecnr), &[], &[], rand));
    }
    #[cfg(feature = "ecgost3410")]
    rows.extend(ecgost3410(context.rand()));
    rows
}

// The key of the params on the curve C, as the private key to sign with or the public one to verify
// with, given to sign
#[allow(dead_code, reason = "unused when no scheme is on")]
fn on<C, F>(params: &dyn Params, sign: F) -> Option<Result<Box<dyn Inner>, AlgoError>>
where
    C: Curve<Scalar = PaddedBigUint> + 'static,
    F: FnOnce(Key<'_, C>) -> Result<Box<dyn Inner>, AlgoError>,
{
    let params = params.as_any();
    if let Some(key) = params.downcast_ref::<EcPrivateKey<C>>() {
        return Some(sign(Key::Private(key)));
    }
    let key = params.downcast_ref::<EcPublicKey<C>>()?;
    Some(sign(Key::Public(key)))
}

#[allow(dead_code, reason = "unused when no scheme is on")]
enum Key<'a, C: Curve<Scalar = PaddedBigUint>> {
    Private(&'a EcPrivateKey<C>),
    Public(&'a EcPublicKey<C>),
}

// Keys a signer that takes either key of C
macro_rules! keyed_by {
    ($key:expr, $signer:expr) => {
        match $key {
            Key::Private(key) => keyed($signer, key),
            Key::Public(key) => keyed($signer, key),
        }
    };
}

#[cfg(feature = "ecdsa")]
fn ecdsa<C>(params: &dyn Params, spec: &Spec) -> Option<Result<Box<dyn Inner>, AlgoError>>
where
    C: Curve<Scalar = PaddedBigUint> + 'static,
{
    on::<C, _>(params, |key| {
        keyed_by!(
            key,
            DsaDigestSigner::new(
                tc_ecdsa_v2::EcdsaSigner::<C, _>::new(k(spec)),
                RowDigest::new(spec.digest.clone()),
            )
        )
    })
}

#[cfg(feature = "ecdsa")]
fn plain_ecdsa<C>(params: &dyn Params, spec: &Spec) -> Option<Result<Box<dyn Inner>, AlgoError>>
where
    C: Curve<Scalar = PaddedBigUint> + 'static,
{
    on::<C, _>(params, |key| {
        keyed_by!(
            key,
            DsaDigestSigner::with_encoding(
                tc_ecdsa_v2::EcdsaSigner::<C, _>::new(k(spec)),
                RowDigest::new(spec.digest.clone()),
                tc_dsa::PlainDsaEncoding,
            )
        )
    })
}

#[cfg(feature = "ecnr")]
fn ecnr<C>(params: &dyn Params, spec: &Spec) -> Option<Result<Box<dyn Inner>, AlgoError>>
where
    C: Curve<Scalar = PaddedBigUint> + 'static,
{
    on::<C, _>(params, |key| {
        keyed_by!(
            key,
            DsaDigestSigner::new(
                tc_ecnr::EcnrSigner::<C, _>::new(k(spec)),
                RowDigest::new(spec.digest.clone()),
            )
        )
    })
}

// GOST R 34.10-2001 over GOST R 34.11-94, and GOST R 34.10-2012 over GOST R 34.11-2012 of 256 and
// 512 bits, with the names, aliases and OIDs of Bouncy Castle's SignerUtilities. The digest is the
// scheme's, so the rows need no digest feature
#[cfg(feature = "ecgost3410")]
fn ecgost3410(rand: Rand) -> Vec<Box<dyn SignerEntry>> {
    type EcgTry = fn(&dyn Params, Rand) -> Option<Result<Box<dyn Inner>, AlgoError>>;

    fn gost<C, D>(
        params: &dyn Params,
        rand: Rand,
        digest: D,
    ) -> Option<Result<Box<dyn Inner>, AlgoError>>
    where
        C: Curve<Scalar = PaddedBigUint> + 'static,
        D: tc_digest::Digest + 'static,
    {
        on::<C, _>(params, |key| {
            let signer = tc_dsa::Gost3410DigestSigner::new(
                tc_ecgost3410::EcGost3410Signer::<C, _>::new(tc_dsa::RandomDsaKCalculator::new(
                    rand(),
                )),
                digest,
            );
            keyed_by!(key, signer)
        })
    }
    fn gost3411<C>(params: &dyn Params, rand: Rand) -> Option<Result<Box<dyn Inner>, AlgoError>>
    where
        C: Curve<Scalar = PaddedBigUint> + 'static,
    {
        gost::<C, _>(params, rand, tc_gost3411::Gost3411Digest::new())
    }
    fn gost3411_2012_256<C>(
        params: &dyn Params,
        rand: Rand,
    ) -> Option<Result<Box<dyn Inner>, AlgoError>>
    where
        C: Curve<Scalar = PaddedBigUint> + 'static,
    {
        gost::<C, _>(params, rand, tc_gost3411::Gost3411_2012_256Digest::new())
    }
    fn gost3411_2012_512<C>(
        params: &dyn Params,
        rand: Rand,
    ) -> Option<Result<Box<dyn Inner>, AlgoError>>
    where
        C: Curve<Scalar = PaddedBigUint> + 'static,
    {
        gost::<C, _>(params, rand, tc_gost3411::Gost3411_2012_512Digest::new())
    }

    let rows: [(&str, &[&str], &[&str], &'static [EcgTry]); 3] = [
        (
            "ECGOST3410",
            &[
                "ECGOST-3410",
                "GOST-3410-2001",
                "GOST3411WITHECGOST3410",
                "GOST3411/ECGOST3410",
            ],
            &["1.2.643.2.2.3"],
            curves!(gost3411),
        ),
        (
            "ECGOST3410-2012-256",
            &[
                "GOST-3410-2012-256",
                "GOST3411WITHECGOST3410-2012-256",
                "GOST3411-2012-256WITHECGOST3410",
                "GOST3411-2012-256WITHECGOST3410-2012-256",
                "GOST3411-2012-256/ECGOST3410",
                "GOST3411-2012-256/ECGOST3410-2012-256",
            ],
            &["1.2.643.7.1.1.3.2"],
            curves!(gost3411_2012_256),
        ),
        (
            "ECGOST3410-2012-512",
            &[
                "GOST-3410-2012-512",
                "GOST3411WITHECGOST3410-2012-512",
                "GOST3411-2012-512WITHECGOST3410",
                "GOST3411-2012-512WITHECGOST3410-2012-512",
                "GOST3411-2012-512/ECGOST3410",
                "GOST3411-2012-512/ECGOST3410-2012-512",
            ],
            &["1.2.643.7.1.1.3.3"],
            curves!(gost3411_2012_512),
        ),
    ];
    rows.into_iter()
        .map(|(name, aliases, oids, tries)| -> Box<dyn SignerEntry> {
            Box::new(Row::new(
                name.to_string(),
                aliases.iter().map(|alias| alias.to_string()).collect(),
                oids,
                Arc::new(move |params| {
                    tries
                        .iter()
                        .find_map(|on| on(params, rand))
                        .unwrap_or(Err(AlgoError::new(ErrorKind::InvalidParams)))
                }),
            ))
        })
        .collect()
}

#[cfg(all(
    test,
    feature = "ecdsa",
    feature = "ecnr",
    feature = "sha1",
    feature = "sha256"
))]
mod tests {
    use crate::generate::KeyPair;
    use crate::params::{EcKeyGenParams, KeyLength};
    use crate::{Algo, AlgoBuilder, DefaultAlgoBuilder, ErrorKind};

    const MESSAGE: &[u8] = b"attack at dawn";

    fn algo() -> Box<dyn Algo> {
        DefaultAlgoBuilder::default().build()
    }

    fn pair(curve: &str) -> KeyPair {
        algo()
            .key_pair_generator()
            .generate_by_name_with("EC", &EcKeyGenParams::new(curve))
            .unwrap()
    }

    fn sign(name: &str, pair: &KeyPair, message: &[u8]) -> Vec<u8> {
        let mut signer = algo().signer().get_by_name(name).unwrap();
        signer.init(pair.private()).unwrap();
        signer.update(message).unwrap();
        signer.sign().unwrap()
    }

    fn verify(name: &str, pair: &KeyPair, message: &[u8], signature: &[u8]) -> bool {
        let mut verifier = algo().signer().get_by_name(name).unwrap();
        verifier.init(pair.public()).unwrap();
        verifier.update(message).unwrap();
        verifier.verify_signature(signature).unwrap()
    }

    // A special prime curve, a generic prime curve and a binary curve
    #[test]
    fn every_scheme_verifies_what_it_signs_on_every_kind_of_curve() {
        for curve in ["secp256r1", "brainpoolP256r1", "sect163k1"] {
            let pair = pair(curve);
            for name in [
                "SHA-256withECDSA",
                "SHA-256withPLAIN-ECDSA",
                "SHA-256withCVC-ECDSA",
                "SHA-1withECNR",
            ] {
                let signature = sign(name, &pair, MESSAGE);
                assert!(
                    verify(name, &pair, MESSAGE, &signature),
                    "{name} on {curve}"
                );
                assert!(
                    !verify(name, &pair, b"attack at dusk", &signature),
                    "{name} on {curve}"
                );
            }
        }
    }

    #[test]
    fn plain_ecdsa_puts_r_and_s_side_by_side_and_ecdsa_gives_der() {
        let pair = pair("secp256r1");
        assert_eq!(sign("SHA-256withPLAIN-ECDSA", &pair, MESSAGE).len(), 64);
        assert_eq!(sign("SHA-256withECDSA", &pair, MESSAGE)[0], 0x30);
    }

    // NONEwithECDSA signs the hash it is given, as SHA-256withECDSA signs the hash of the message
    #[cfg(feature = "null-digest")]
    #[test]
    fn none_with_ecdsa_over_the_hash_verifies_as_sha256_with_ecdsa() {
        let pair = pair("secp256r1");
        let mut digest = algo().digest().get_by_name("SHA-256").unwrap();
        digest.try_update(MESSAGE).unwrap();
        let hash = digest.finalize().unwrap();

        let signature = sign("NONEwithECDSA", &pair, &hash);
        assert!(verify("SHA-256withECDSA", &pair, MESSAGE, &signature));
        let signature = sign("SHA-256withECDSA", &pair, MESSAGE);
        assert!(verify("ECDSAWITHNONE", &pair, &hash, &signature));
    }

    #[test]
    fn the_rows_are_found_by_the_names_and_oids_of_bouncy_castle() {
        let algo = algo();
        let signers = algo.signer();
        for name in [
            "ECDSA",
            "SHA256/ECDSA",
            "ECDSAWITHSHA-256",
            "sha256withplain-ecdsa",
            "SHA-1WITHECNR",
        ] {
            assert!(signers.get_by_name(name).is_ok(), "{name}");
        }
        for oid in [
            "1.2.840.10045.4.1",
            "1.2.840.10045.4.3.2",
            "0.4.0.127.0.7.1.1.4.1.3",
            "0.4.0.127.0.7.2.2.2.2.3",
        ] {
            assert!(signers.get_by_oid(&oid.parse().unwrap()).is_ok(), "{oid}");
        }
    }

    #[test]
    fn params_of_another_type_and_a_public_key_that_signs_are_refused() {
        let mut signer = algo().signer().get_by_name("SHA-256withECDSA").unwrap();
        let error = signer.init(&KeyLength::new(1)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);

        let pair = pair("secp256r1");
        signer.init(pair.public()).unwrap();
        signer.update(MESSAGE).unwrap();
        let error = signer.sign().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
    }
}

#[cfg(all(test, feature = "ecgost3410"))]
mod gost_tests {
    use crate::params::EcKeyGenParams;
    use crate::{AlgoBuilder, DefaultAlgoBuilder};

    #[test]
    fn ecgost3410_verifies_what_it_signs_on_the_gost_curves() {
        let algo = DefaultAlgoBuilder::default().build();
        for (curve, names, oid) in [
            (
                "GostR3410-2001-CryptoPro-A",
                ["ECGOST3410", "GOST-3410-2001"],
                "1.2.643.2.2.3",
            ),
            (
                "Tc26-Gost-3410-12-512-paramSetA",
                ["ECGOST3410-2012-512", "GOST3411-2012-512/ECGOST3410"],
                "1.2.643.7.1.1.3.3",
            ),
            (
                "GostR3410-2001-CryptoPro-A",
                ["ECGOST3410-2012-256", "GOST-3410-2012-256"],
                "1.2.643.7.1.1.3.2",
            ),
        ] {
            let pair = algo
                .key_pair_generator()
                .generate_by_name_with("ECGOST3410", &EcKeyGenParams::new(curve))
                .unwrap();
            for name in names {
                let mut signer = algo.signer().get_by_name(name).unwrap();
                signer.init(pair.private()).unwrap();
                signer.update(b"attack at dawn").unwrap();
                let signature = signer.sign().unwrap();

                let mut verifier = algo.signer().get_by_name(name).unwrap();
                verifier.init(pair.public()).unwrap();
                verifier.update(b"attack at dawn").unwrap();
                assert!(verifier.verify_signature(&signature).unwrap(), "{name}");
                verifier.update(b"attack at dusk").unwrap();
                assert!(!verifier.verify_signature(&signature).unwrap(), "{name}");
            }
            assert!(
                algo.signer().get_by_oid(&oid.parse().unwrap()).is_ok(),
                "{oid}"
            );
        }
    }
}
