use core::error::Error;

use tc_agreement::AgreementInit;
use tc_agreement_kdf::{AgreementWithKdf, UkmParams};
use tc_asn1::Asn1Oid;
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_bigint::PaddedBigUint;
use tc_digest::Digest;
use tc_ec_core::Curve;
#[cfg(any(feature = "ecdh", feature = "ecdhc"))]
use tc_ec_key::EcPrivateKey;
use tc_ecdh_kek::EcdhKek;

use super::typed::{Erased, Inner, init_as, init_with};
use crate::agreement::{Agreement, AgreementEntry};
use crate::params::ec_curves::ct_curves;
use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind, Params};

type Try = fn(&dyn Params) -> Option<Result<Box<dyn Inner>, AlgoError>>;
type KdfTry =
    fn(&dyn Params, &AlgorithmIdentifier, u32) -> Option<Result<Box<dyn Inner>, AlgoError>>;

// The rows of the agreements over EC keys, to give to DefaultAlgoBuilder::reg_agreement: ECDH,
// ECDHC and ECMQV, and their variants with the KDF of RFC 5753 over SHA-1 to SHA-512, with the
// names, aliases and OIDs of Bouncy Castle's AgreementUtilities. As in ECIES, the curve comes from
// the keys: each row tries the constant-time curve types in turn when it is initialized. A KDF row
// is made by get_with_kdf_by_name or get_with_kdf_by_oid, as Bouncy Castle's
// GetBasicAgreementWithKdf makes it, and exists when the features of both its agreement and its
// digest are on
pub(super) fn ec(_context: &DefaultAlgoContext) -> Vec<Box<dyn AgreementEntry>> {
    let mut rows: Vec<Box<dyn AgreementEntry>> = Vec::new();
    #[cfg(feature = "ecdh")]
    rows.push(row("ECDH", &[], ct_curves!(ecdh)));
    #[cfg(feature = "ecdhc")]
    rows.push(row("ECDHC", &["ECCDH"], ct_curves!(ecdhc)));
    #[cfg(feature = "ecmqv")]
    rows.push(row("ECMQV", &[], ct_curves!(ecmqv)));

    #[cfg(all(feature = "ecdh", feature = "sha1"))]
    rows.push(kdf_row(
        "ECDHWITHSHA1KDF",
        &["DHWITHSHA1KDF"],
        "1.3.133.16.840.63.0.2",
        ct_curves!(ecdh_sha1),
    ));
    #[cfg(all(feature = "ecdh", feature = "sha224"))]
    rows.push(kdf_row(
        "ECDHWITHSHA224KDF",
        &[],
        "1.3.132.1.11.0",
        ct_curves!(ecdh_sha224),
    ));
    #[cfg(all(feature = "ecdh", feature = "sha256"))]
    rows.push(kdf_row(
        "ECDHWITHSHA256KDF",
        &[],
        "1.3.132.1.11.1",
        ct_curves!(ecdh_sha256),
    ));
    #[cfg(all(feature = "ecdh", feature = "sha384"))]
    rows.push(kdf_row(
        "ECDHWITHSHA384KDF",
        &[],
        "1.3.132.1.11.2",
        ct_curves!(ecdh_sha384),
    ));
    #[cfg(all(feature = "ecdh", feature = "sha512"))]
    rows.push(kdf_row(
        "ECDHWITHSHA512KDF",
        &[],
        "1.3.132.1.11.3",
        ct_curves!(ecdh_sha512),
    ));

    #[cfg(all(feature = "ecdhc", feature = "sha1"))]
    rows.push(kdf_row(
        "ECCDHWITHSHA1KDF",
        &[],
        "1.3.133.16.840.63.0.3",
        ct_curves!(ecdhc_sha1),
    ));
    #[cfg(all(feature = "ecdhc", feature = "sha224"))]
    rows.push(kdf_row(
        "ECCDHWITHSHA224KDF",
        &[],
        "1.3.132.1.14.0",
        ct_curves!(ecdhc_sha224),
    ));
    #[cfg(all(feature = "ecdhc", feature = "sha256"))]
    rows.push(kdf_row(
        "ECCDHWITHSHA256KDF",
        &[],
        "1.3.132.1.14.1",
        ct_curves!(ecdhc_sha256),
    ));
    #[cfg(all(feature = "ecdhc", feature = "sha384"))]
    rows.push(kdf_row(
        "ECCDHWITHSHA384KDF",
        &[],
        "1.3.132.1.14.2",
        ct_curves!(ecdhc_sha384),
    ));
    #[cfg(all(feature = "ecdhc", feature = "sha512"))]
    rows.push(kdf_row(
        "ECCDHWITHSHA512KDF",
        &[],
        "1.3.132.1.14.3",
        ct_curves!(ecdhc_sha512),
    ));

    #[cfg(all(feature = "ecmqv", feature = "sha1"))]
    rows.push(kdf_row(
        "ECMQVWITHSHA1KDF",
        &[],
        "1.3.133.16.840.63.0.16",
        ct_curves!(ecmqv_sha1),
    ));
    #[cfg(all(feature = "ecmqv", feature = "sha224"))]
    rows.push(kdf_row(
        "ECMQVWITHSHA224KDF",
        &[],
        "1.3.132.1.15.0",
        ct_curves!(ecmqv_sha224),
    ));
    #[cfg(all(feature = "ecmqv", feature = "sha256"))]
    rows.push(kdf_row(
        "ECMQVWITHSHA256KDF",
        &[],
        "1.3.132.1.15.1",
        ct_curves!(ecmqv_sha256),
    ));
    #[cfg(all(feature = "ecmqv", feature = "sha384"))]
    rows.push(kdf_row(
        "ECMQVWITHSHA384KDF",
        &[],
        "1.3.132.1.15.2",
        ct_curves!(ecmqv_sha384),
    ));
    #[cfg(all(feature = "ecmqv", feature = "sha512"))]
    rows.push(kdf_row(
        "ECMQVWITHSHA512KDF",
        &[],
        "1.3.132.1.15.3",
        ct_curves!(ecmqv_sha512),
    ));
    rows
}

struct Row {
    name: &'static str,
    aliases: Vec<String>,
    tries: &'static [Try],
}

fn row(name: &'static str, aliases: &[&str], tries: &'static [Try]) -> Box<dyn AgreementEntry> {
    Box::new(Row {
        name,
        aliases: aliases.iter().map(|alias| alias.to_string()).collect(),
        tries,
    })
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        self.name
    }

    fn aliases(&self) -> &[String] {
        &self.aliases
    }
}

impl AgreementEntry for Row {
    fn create(&self) -> Option<Box<dyn Agreement>> {
        let tries = self.tries;
        Some(Erased::boxed(move |params: &dyn Params| {
            tries.iter().find_map(|init| init(params))
        }))
    }
}

#[allow(dead_code)]
struct KdfRow {
    name: &'static str,
    aliases: Vec<String>,
    oids: Vec<Asn1Oid>,
    tries: &'static [KdfTry],
}

#[allow(dead_code)]
fn kdf_row(
    name: &'static str,
    aliases: &[&str],
    oid: &str,
    tries: &'static [KdfTry],
) -> Box<dyn AgreementEntry> {
    Box::new(KdfRow {
        name,
        aliases: aliases.iter().map(|alias| alias.to_string()).collect(),
        oids: vec![oid.parse().expect("a dotted OID")],
        tries,
    })
}

impl EntryBase for KdfRow {
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

impl AgreementEntry for KdfRow {
    // Without a key-wrap algorithm there is no key size, so only create_with_kdf makes it
    fn create(&self) -> Option<Box<dyn Agreement>> {
        None
    }

    // The KDF derives a key of the default size of `wrap`; a key-wrap algorithm without one is
    // InvalidParams
    fn create_with_kdf(
        &self,
        wrap: &AlgorithmIdentifier,
    ) -> Option<Result<Box<dyn Agreement>, AlgoError>> {
        let Some(bits) = wrap_key_size(wrap.algorithm()) else {
            return Some(Err(AlgoError::new(ErrorKind::InvalidParams)));
        };
        let (wrap, tries) = (wrap.clone(), self.tries);
        Some(Ok(Erased::boxed(move |params: &dyn Params| {
            tries.iter().find_map(|init| init(params, &wrap, bits))
        })))
    }
}

// The default key sizes Bouncy Castle's GeneratorUtilities gives the key-wrap algorithms, in bits
#[allow(dead_code)]
fn wrap_key_size(oid: &Asn1Oid) -> Option<u32> {
    const SIZES: &[(&str, u32)] = &[
        ("2.16.840.1.101.3.4.1.5", 128),
        ("2.16.840.1.101.3.4.1.8", 128),
        ("2.16.840.1.101.3.4.1.25", 192),
        ("2.16.840.1.101.3.4.1.28", 192),
        ("2.16.840.1.101.3.4.1.45", 256),
        ("2.16.840.1.101.3.4.1.48", 256),
        ("1.2.410.200046.1.1.40", 128),
        ("1.2.410.200046.1.1.43", 128),
        ("1.2.410.200046.1.1.41", 192),
        ("1.2.410.200046.1.1.44", 192),
        ("1.2.410.200046.1.1.42", 256),
        ("1.2.410.200046.1.1.45", 256),
        ("1.2.392.200011.61.1.1.3.2", 128),
        ("1.2.392.200011.61.1.1.3.3", 192),
        ("1.2.392.200011.61.1.1.3.4", 256),
        ("1.2.840.113549.1.9.16.3.6", 192),
        ("1.2.840.113549.1.9.16.3.7", 128),
        ("1.2.410.200004.7.1.1.1", 128),
    ];
    SIZES
        .iter()
        .find(|(dotted, _)| dotted.parse::<Asn1Oid>().is_ok_and(|known| &known == oid))
        .map(|&(_, bits)| bits)
}

// Inits the KDF agreement with a UkmParams of a P, or with a P alone, which has no UKM, as Bouncy
// Castle takes either; None for params of another type
#[allow(dead_code)]
fn ukm_or_key<P, A>(agreement: A, params: &dyn Params) -> Option<Result<Box<dyn Inner>, AlgoError>>
where
    P: Clone + 'static,
    A: AgreementInit<UkmParams<P>> + tc_agreement::Agreement + 'static,
    A::PublicKey: Sized + 'static,
    <A as AgreementInit<UkmParams<P>>>::Error: Error + Send + Sync + 'static,
    <A as tc_agreement::Agreement>::Error: Error + Send + Sync + 'static,
{
    let any = params.as_any();
    if let Some(params) = any.downcast_ref::<UkmParams<P>>() {
        return Some(init_with(agreement, params));
    }
    let key = any.downcast_ref::<P>()?;
    Some(init_with(agreement, &UkmParams::new(key.clone())))
}

#[cfg(feature = "ecdh")]
use tc_ecdh_v2::EcdhBasicAgreement;
#[cfg(feature = "ecdhc")]
use tc_ecdh_v2::EcdhcBasicAgreement;
#[cfg(feature = "ecmqv")]
use tc_ecmqv::{EcMqvBasicAgreement, MqvPrivateParams};

#[cfg(feature = "ecdh")]
fn ecdh<C: Curve<Scalar = PaddedBigUint> + 'static>(
    params: &dyn Params,
) -> Option<Result<Box<dyn Inner>, AlgoError>> {
    init_as::<EcPrivateKey<C>, _>(EcdhBasicAgreement::<C>::new(), params)
}

#[cfg(feature = "ecdhc")]
fn ecdhc<C: Curve<Scalar = PaddedBigUint> + 'static>(
    params: &dyn Params,
) -> Option<Result<Box<dyn Inner>, AlgoError>> {
    init_as::<EcPrivateKey<C>, _>(EcdhcBasicAgreement::<C>::new(), params)
}

// Its params are a MqvPrivateParams of the static and ephemeral private keys, and the other side's
// a MqvPublicParams
#[cfg(feature = "ecmqv")]
fn ecmqv<C: Curve<Scalar = PaddedBigUint> + 'static>(
    params: &dyn Params,
) -> Option<Result<Box<dyn Inner>, AlgoError>> {
    init_as::<MqvPrivateParams<C>, _>(EcMqvBasicAgreement::<C>::new(), params)
}

#[cfg(feature = "ecdh")]
#[allow(dead_code)]
fn ecdh_kdf<C, D>(
    params: &dyn Params,
    wrap: &AlgorithmIdentifier,
    bits: u32,
) -> Option<Result<Box<dyn Inner>, AlgoError>>
where
    C: Curve<Scalar = PaddedBigUint> + 'static,
    D: Digest + Default + 'static,
{
    let kdf = EcdhKek::new(D::default());
    let agreement = AgreementWithKdf::new(EcdhBasicAgreement::<C>::new(), kdf, wrap.clone(), bits);
    ukm_or_key::<EcPrivateKey<C>, _>(agreement, params)
}

#[cfg(feature = "ecdhc")]
#[allow(dead_code)]
fn ecdhc_kdf<C, D>(
    params: &dyn Params,
    wrap: &AlgorithmIdentifier,
    bits: u32,
) -> Option<Result<Box<dyn Inner>, AlgoError>>
where
    C: Curve<Scalar = PaddedBigUint> + 'static,
    D: Digest + Default + 'static,
{
    let kdf = EcdhKek::new(D::default());
    let agreement = AgreementWithKdf::new(EcdhcBasicAgreement::<C>::new(), kdf, wrap.clone(), bits);
    ukm_or_key::<EcPrivateKey<C>, _>(agreement, params)
}

#[cfg(feature = "ecmqv")]
#[allow(dead_code)]
fn ecmqv_kdf<C, D>(
    params: &dyn Params,
    wrap: &AlgorithmIdentifier,
    bits: u32,
) -> Option<Result<Box<dyn Inner>, AlgoError>>
where
    C: Curve<Scalar = PaddedBigUint> + 'static,
    D: Digest + Default + 'static,
{
    let kdf = EcdhKek::new(D::default());
    let agreement = AgreementWithKdf::new(EcMqvBasicAgreement::<C>::new(), kdf, wrap.clone(), bits);
    ukm_or_key::<MqvPrivateParams<C>, _>(agreement, params)
}

// One function per agreement and digest, generic over the curve alone, as ct_curves! takes them
macro_rules! with_digest {
    ($($feature:literal, $digest_feature:literal, $name:ident, $kdf:ident, $digest:ty;)*) => {
        $(
            #[cfg(all(feature = $feature, feature = $digest_feature))]
            fn $name<C: Curve<Scalar = PaddedBigUint> + 'static>(
                params: &dyn Params,
                wrap: &AlgorithmIdentifier,
                bits: u32,
            ) -> Option<Result<Box<dyn Inner>, AlgoError>> {
                $kdf::<C, $digest>(params, wrap, bits)
            }
        )*
    };
}

with_digest! {
    "ecdh", "sha1", ecdh_sha1, ecdh_kdf, tc_sha::Sha1Digest;
    "ecdh", "sha224", ecdh_sha224, ecdh_kdf, tc_sha::Sha224Digest;
    "ecdh", "sha256", ecdh_sha256, ecdh_kdf, tc_sha::Sha256Digest;
    "ecdh", "sha384", ecdh_sha384, ecdh_kdf, tc_sha::Sha384Digest;
    "ecdh", "sha512", ecdh_sha512, ecdh_kdf, tc_sha::Sha512Digest;
    "ecdhc", "sha1", ecdhc_sha1, ecdhc_kdf, tc_sha::Sha1Digest;
    "ecdhc", "sha224", ecdhc_sha224, ecdhc_kdf, tc_sha::Sha224Digest;
    "ecdhc", "sha256", ecdhc_sha256, ecdhc_kdf, tc_sha::Sha256Digest;
    "ecdhc", "sha384", ecdhc_sha384, ecdhc_kdf, tc_sha::Sha384Digest;
    "ecdhc", "sha512", ecdhc_sha512, ecdhc_kdf, tc_sha::Sha512Digest;
    "ecmqv", "sha1", ecmqv_sha1, ecmqv_kdf, tc_sha::Sha1Digest;
    "ecmqv", "sha224", ecmqv_sha224, ecmqv_kdf, tc_sha::Sha224Digest;
    "ecmqv", "sha256", ecmqv_sha256, ecmqv_kdf, tc_sha::Sha256Digest;
    "ecmqv", "sha384", ecmqv_sha384, ecmqv_kdf, tc_sha::Sha384Digest;
    "ecmqv", "sha512", ecmqv_sha512, ecmqv_kdf, tc_sha::Sha512Digest;
}

#[cfg(test)]
mod tests {
    use rand::rngs::SysRng;
    use rand_core::UnwrapErr;
    use tc_asn1_x509::alg::AlgorithmIdentifier;
    use tc_ec_key::{EcPrivateKey, EcPublicKey};
    use tc_fp_custom::{SecP256R1FieldElement, SecPCtCurve};

    use crate::agreement::Agreement;
    use crate::params::KeyLength;
    use crate::params::ec_curves::by_name;
    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind, Params};

    type P256 = &'static SecPCtCurve<SecP256R1FieldElement>;
    type Pair = (EcPublicKey<P256>, EcPrivateKey<P256>);

    fn pair(curve: &str) -> (Box<dyn Params>, Box<dyn Params>) {
        (by_name(curve).unwrap().generate)(&mut UnwrapErr(SysRng)).unwrap()
    }

    fn p256() -> Pair {
        let (public, private) = pair("P-256");
        (
            public
                .as_any()
                .downcast_ref::<EcPublicKey<P256>>()
                .unwrap()
                .clone(),
            private
                .as_any()
                .downcast_ref::<EcPrivateKey<P256>>()
                .unwrap()
                .clone(),
        )
    }

    fn secret(agreement: &dyn Agreement, public_key: &dyn Params) -> Vec<u8> {
        let mut secret = vec![0; agreement.agreement_size()];
        agreement
            .calculate_agreement(public_key, &mut secret)
            .unwrap();
        secret
    }

    fn agreed(name: &str, private: &dyn Params) -> Box<dyn Agreement> {
        let algo = DefaultAlgoBuilder::default().build();
        let mut agreement = algo.agreement().get_by_name(name).unwrap();
        agreement.init(private).unwrap();
        agreement
    }

    fn aes128_wrap() -> AlgorithmIdentifier {
        AlgorithmIdentifier::new("2.16.840.1.101.3.4.1.5".parse().unwrap())
    }

    #[test]
    fn both_sides_of_ecdh_and_ecdhc_calculate_the_same_secret_of_the_field_size() {
        let (alice_public, alice_private) = p256();
        let (bob_public, bob_private) = p256();
        for name in ["ECDH", "ECDHC", "ECCDH"] {
            let alice = secret(agreed(name, &alice_private).as_ref(), &bob_public);
            let bob = secret(agreed(name, &bob_private).as_ref(), &alice_public);
            assert_eq!(alice, bob, "{name}");
            assert_eq!(alice.len(), 32, "{name}");
        }
    }

    #[test]
    fn both_sides_of_ecmqv_calculate_the_same_secret_from_static_and_ephemeral_keys() {
        use tc_ecmqv::{MqvPrivateParams, MqvPublicParams};
        let (alice, bob) = ([p256(), p256()], [p256(), p256()]);
        let private =
            |keys: &[Pair; 2]| MqvPrivateParams::new(keys[0].1.clone(), keys[1].1.clone());
        let public = |keys: &[Pair; 2]| MqvPublicParams::new(keys[0].0.clone(), keys[1].0.clone());

        let alice_secret = secret(agreed("ECMQV", &private(&alice)).as_ref(), &public(&bob));
        let bob_secret = secret(agreed("ECMQV", &private(&bob)).as_ref(), &public(&alice));
        assert_eq!(alice_secret, bob_secret);
        assert_eq!(alice_secret.len(), 32);
    }

    #[test]
    fn a_kdf_row_needs_a_key_wrap_algorithm_and_derives_a_key_of_its_size() {
        let algo = DefaultAlgoBuilder::default().build();
        let error = algo
            .agreement()
            .get_by_name("ECDHWITHSHA256KDF")
            .err()
            .unwrap();
        assert_eq!(error.kind(), ErrorKind::UnknownAgreement);

        let (alice_public, alice_private) = p256();
        let (bob_public, bob_private) = p256();
        let ukm = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let with_kdf = |private: EcPrivateKey<P256>| {
            let mut agreement = algo
                .agreement()
                .get_with_kdf_by_oid(&"1.3.132.1.11.1".parse().unwrap(), &aes128_wrap())
                .unwrap();
            agreement
                .init(&crate::params::UkmParams::new(private).with_ukm(ukm.clone()))
                .unwrap();
            agreement
        };

        let alice = secret(with_kdf(alice_private).as_ref(), &bob_public);
        let bob = secret(with_kdf(bob_private).as_ref(), &alice_public);
        assert_eq!(alice, bob);
        assert_eq!(alice.len(), 16);
    }

    #[test]
    fn a_kdf_row_takes_a_private_key_without_a_ukm_and_refuses_an_unknown_wrap() {
        let algo = DefaultAlgoBuilder::default().build();
        let (public, private) = p256();
        let mut agreement = algo
            .agreement()
            .get_with_kdf_by_name("DHWITHSHA1KDF", &aes128_wrap())
            .unwrap();
        agreement.init(&private).unwrap();
        assert_eq!(secret(agreement.as_ref(), &public).len(), 16);

        let unknown = AlgorithmIdentifier::new("1.2.3.4".parse().unwrap());
        let error = algo
            .agreement()
            .get_with_kdf_by_name("ECMQVWITHSHA512KDF", &unknown)
            .err()
            .unwrap();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
        let error = algo
            .agreement()
            .get_with_kdf_by_name("ECDH", &aes128_wrap())
            .err()
            .unwrap();
        assert_eq!(error.kind(), ErrorKind::UnknownAgreement);
    }

    #[test]
    fn calculating_needs_an_init_with_keys_of_the_row_and_of_one_curve() {
        let algo = DefaultAlgoBuilder::default().build();
        let (public, private) = p256();
        let mut agreement = algo.agreement().get_by_name("ECDH").unwrap();

        let mut output = [0; 32];
        let error = agreement
            .calculate_agreement(&public, &mut output)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
        let error = agreement.init(&KeyLength::new(1)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);

        agreement.init(&private).unwrap();
        let (other_curve, _) = pair("P-384");
        let error = agreement
            .calculate_agreement(other_curve.as_ref(), &mut output)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
        let error = agreement
            .calculate_agreement(&public, &mut [0; 31])
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DataLength);
    }
}
