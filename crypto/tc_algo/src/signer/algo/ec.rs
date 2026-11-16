use std::sync::Arc;

use rand_core::CryptoRng;
use tc_bigint::PaddedBigUint;
use tc_dsa::{DsaDigestSigner, DsaDigestSignerError, RandomDsaKCalculator};
use tc_ec_core::Curve;
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_f2m_curve::F2mCtCurve;
use tc_f2m_custom::{
    SecT113FieldElement, SecT131FieldElement, SecT163FieldElement, SecT193FieldElement,
    SecT233FieldElement, SecT239FieldElement, SecT283FieldElement, SecT409FieldElement,
    SecT571FieldElement, SecTCtCurve,
};
use tc_fp_curve::FpCtCurve;
use tc_fp_custom::{
    SM2P256V1FieldElement, SecP128R1FieldElement, SecP160R1FieldElement, SecP160R2FieldElement,
    SecP192K1FieldElement, SecP192R1FieldElement, SecP224K1FieldElement, SecP224R1FieldElement,
    SecP256K1FieldElement, SecP256R1FieldElement, SecP384R1FieldElement, SecP521R1FieldElement,
    SecPCtCurve,
};

use super::row::{Inner, Kind, Row, digest_names, digests, keyed, oids_of, signer_digest_name};
use crate::digest::{DigestEntry, RowDigest};
use crate::signer::SignerEntry;
use crate::{AlgoError, DefaultAlgoContext, ErrorKind, Params};

type Rand = fn() -> Box<dyn CryptoRng>;
type KCalculator = RandomDsaKCalculator<Box<dyn CryptoRng>>;

// What a row signs with, and the digest and randomness it takes
struct Spec {
    digest: Arc<dyn DigestEntry>,
    rand: Rand,
}

// A signer over the curve C, keyed, when the params are a key on C; None when they are not
type Try = fn(&dyn Params, &Spec) -> Option<Result<Box<dyn Inner>, AlgoError>>;

// The curve types the rows take: the generic ones of tc_fp_curve and tc_f2m_curve, which hold any
// prime or binary curve, and the special ones of tc_fp_custom and tc_f2m_custom, those of the keys
// of the EC key pair generator
macro_rules! curves {
    ($on:ident) => {
        &[
            $on::<&'static FpCtCurve<'static>>,
            $on::<&'static F2mCtCurve>,
            $on::<&'static SecPCtCurve<SecP128R1FieldElement>>,
            $on::<&'static SecPCtCurve<SecP160R1FieldElement>>,
            $on::<&'static SecPCtCurve<SecP160R2FieldElement>>,
            $on::<&'static SecPCtCurve<SecP192K1FieldElement>>,
            $on::<&'static SecPCtCurve<SecP192R1FieldElement>>,
            $on::<&'static SecPCtCurve<SecP224K1FieldElement>>,
            $on::<&'static SecPCtCurve<SecP224R1FieldElement>>,
            $on::<&'static SecPCtCurve<SecP256K1FieldElement>>,
            $on::<&'static SecPCtCurve<SecP256R1FieldElement>>,
            $on::<&'static SecPCtCurve<SecP384R1FieldElement>>,
            $on::<&'static SecPCtCurve<SecP521R1FieldElement>>,
            $on::<&'static SecPCtCurve<SM2P256V1FieldElement>>,
            $on::<&'static SecTCtCurve<SecT113FieldElement>>,
            $on::<&'static SecTCtCurve<SecT131FieldElement>>,
            $on::<&'static SecTCtCurve<SecT163FieldElement>>,
            $on::<&'static SecTCtCurve<SecT193FieldElement>>,
            $on::<&'static SecTCtCurve<SecT233FieldElement>>,
            $on::<&'static SecTCtCurve<SecT239FieldElement>>,
            $on::<&'static SecTCtCurve<SecT283FieldElement>>,
            $on::<&'static SecTCtCurve<SecT409FieldElement>>,
            $on::<&'static SecTCtCurve<SecT571FieldElement>>,
        ]
    };
}

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

// The rows of the DSA-like signatures over EC keys, to give to DefaultAlgoBuilder::reg_signer, with
// the names, aliases and OIDs of Bouncy Castle's SignerUtilities, over each digest row that is on:
// ECDSA, with its signature in DER; PLAIN-ECDSA and CVC-ECDSA, ECDSA with r and s side by side; and
// ECNR. NONE signs a message that is the hash itself. Each takes an EcPrivateKey to sign and an
// EcPublicKey to verify, on any curve of the EC key pair generator, and draws k at random, as
// Bouncy Castle does
pub(super) fn ec(context: &DefaultAlgoContext) -> Vec<Box<dyn SignerEntry>> {
    let rand: Rand = context.rand();
    let mut rows: Vec<Box<dyn SignerEntry>> = Vec::new();
    for digest in digests(context) {
        #[cfg(feature = "ecdsa")]
        {
            rows.push(row(&digest, "ECDSA", curves!(ecdsa), rand));
            rows.push(row(&digest, "PLAIN-ECDSA", curves!(plain_ecdsa), rand));
            rows.push(row(&digest, "CVC-ECDSA", curves!(plain_ecdsa), rand));
        }
        #[cfg(feature = "ecnr")]
        rows.push(row(&digest, "ECNR", curves!(ecnr), rand));
    }
    rows
}

// The row of a digest and a scheme, named SHA-256withECDSA, also SHA256WITHECDSA, SHA-256/ECDSA
// and ECDSAWITHSHA-256, after every name of the digest. ECDSA alone is SHA-1withECDSA, as in Bouncy
// Castle
fn row(
    digest: &Arc<dyn DigestEntry>,
    scheme: &str,
    curves: &'static [Try],
    rand: Rand,
) -> Box<dyn SignerEntry> {
    let name = format!("{}with{scheme}", signer_digest_name(&**digest));
    let mut aliases: Vec<String> = digest_names(&**digest)
        .iter()
        .flat_map(|digest| {
            [
                format!("{digest}WITH{scheme}"),
                format!("{digest}/{scheme}"),
                format!("{scheme}WITH{digest}"),
            ]
        })
        .collect();
    if digest.name() == "SHA-1" && scheme == "ECDSA" {
        aliases.push("ECDSA".to_string());
    }
    #[cfg(feature = "ecdsa")]
    let oids = oids_of(ECDSA_OIDS, &name);
    #[cfg(not(feature = "ecdsa"))]
    let oids = oids_of(&[], &name);
    let spec = Arc::new(Spec {
        digest: digest.clone(),
        rand,
    });
    Box::new(Row::new(
        name,
        aliases,
        oids,
        Arc::new(move |params| {
            curves
                .iter()
                .find_map(|on| on(params, &spec))
                .unwrap_or(Err(AlgoError::new(ErrorKind::InvalidParams)))
        }),
    ))
}

// The key of the params on the curve C, as the private key to sign with or the public one to verify
// with, given to sign
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

enum Key<'a, C: Curve<Scalar = PaddedBigUint>> {
    Private(&'a EcPrivateKey<C>),
    Public(&'a EcPublicKey<C>),
}

fn k(spec: &Spec) -> KCalculator {
    RandomDsaKCalculator::new((spec.rand)())
}

#[cfg(feature = "ecdsa")]
fn ecdsa<C>(params: &dyn Params, spec: &Spec) -> Option<Result<Box<dyn Inner>, AlgoError>>
where
    C: Curve<Scalar = PaddedBigUint> + 'static,
{
    on::<C, _>(params, |key| {
        let signer = DsaDigestSigner::new(
            tc_ecdsa_v2::EcdsaSigner::<C, _>::new(k(spec)),
            RowDigest::new(spec.digest.clone()),
        );
        match key {
            Key::Private(key) => keyed(signer, key),
            Key::Public(key) => keyed(signer, key),
        }
    })
}

#[cfg(feature = "ecdsa")]
fn plain_ecdsa<C>(params: &dyn Params, spec: &Spec) -> Option<Result<Box<dyn Inner>, AlgoError>>
where
    C: Curve<Scalar = PaddedBigUint> + 'static,
{
    on::<C, _>(params, |key| {
        let signer = DsaDigestSigner::with_encoding(
            tc_ecdsa_v2::EcdsaSigner::<C, _>::new(k(spec)),
            RowDigest::new(spec.digest.clone()),
            tc_dsa::PlainDsaEncoding,
        );
        match key {
            Key::Private(key) => keyed(signer, key),
            Key::Public(key) => keyed(signer, key),
        }
    })
}

#[cfg(feature = "ecnr")]
fn ecnr<C>(params: &dyn Params, spec: &Spec) -> Option<Result<Box<dyn Inner>, AlgoError>>
where
    C: Curve<Scalar = PaddedBigUint> + 'static,
{
    on::<C, _>(params, |key| {
        let signer = DsaDigestSigner::new(
            tc_ecnr::EcnrSigner::<C, _>::new(k(spec)),
            RowDigest::new(spec.digest.clone()),
        );
        match key {
            Key::Private(key) => keyed(signer, key),
            Key::Public(key) => keyed(signer, key),
        }
    })
}

impl<E> Kind for DsaDigestSignerError<E> {
    fn kind(&self) -> ErrorKind {
        match self {
            DsaDigestSignerError::NotInitialized
            | DsaDigestSignerError::NotForSigning
            | DsaDigestSignerError::NotForVerifying => ErrorKind::NotInitialized,
            _ => ErrorKind::DataLength,
        }
    }
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
