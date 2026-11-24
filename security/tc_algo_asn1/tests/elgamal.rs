use tc_algo::generate::KeyPair;
use tc_algo::params::key::{ElGamalParameters, ElGamalPrivateKey, ElGamalPublicKey};
use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};
use tc_algo_asn1::{AlgoAsn1, AlgoAsn1Builder, AlgoAsn1Error, DefaultAlgoAsn1Builder};
use tc_asn1::{Asn1Object, Asn1OctetString};
use tc_asn1_pkcs::PrivateKeyInfo;
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::cert::SubjectPublicKeyInfo;
use tc_dh_key::standard_groups::rfc3526_1536;

fn asn1() -> Box<dyn AlgoAsn1> {
    DefaultAlgoAsn1Builder::default().build()
}

// A pair in the 1536-bit group of RFC 3526
fn pair() -> KeyPair {
    let group = rfc3526_1536();
    let params = ElGamalParameters::new(group.p().clone(), group.g().clone());
    DefaultAlgoBuilder::default()
        .build()
        .key_pair_generator()
        .generate_by_name_with("ELGAMAL", &params)
        .unwrap()
}

// ElGamalAlgorithm with SEQUENCE { p, g }, as Bouncy Castle's factories write it
fn assert_parameters(algorithm: &AlgorithmIdentifier) {
    assert_eq!(algorithm.algorithm().to_string(), "1.3.14.7.2.1.1");
    let Some(Asn1Object::SequenceOf(sequence)) = algorithm.parameters() else {
        panic!("ElGamalParameter is a SEQUENCE");
    };
    let [Asn1Object::Integer(p), Asn1Object::Integer(g)] = sequence.elements() else {
        panic!("ElGamalParameter is p and g");
    };
    assert_eq!(p.as_unsigned_bytes().unwrap().len(), 192);
    assert_eq!(g.as_unsigned_bytes().unwrap(), [2]);
}

#[test]
fn an_elgamal_public_key_writes_the_spki_of_bouncy_castle_and_reads_back() {
    let asn1 = asn1();
    let pair = pair();
    let spki = asn1.spki().encode(pair.public()).unwrap();
    assert_parameters(spki.algorithm());

    let key = asn1.spki().decode(&spki).unwrap();
    let key = key.as_any().downcast_ref::<ElGamalPublicKey>().unwrap();
    let original = pair
        .public()
        .as_any()
        .downcast_ref::<ElGamalPublicKey>()
        .unwrap();
    assert_eq!(key.y(), original.y());
    assert_eq!(key.params().p(), original.params().p());
    assert_eq!(key.params().g(), original.params().g());
    assert_eq!(asn1.spki().encode(key).unwrap(), spki);
}

#[test]
fn an_elgamal_private_key_writes_the_pkcs8_of_bouncy_castle_and_reads_back() {
    let asn1 = asn1();
    let pair = pair();
    let info = asn1.pkcs8().encode(pair.private()).unwrap();
    assert_parameters(info.algorithm());

    let key = asn1.pkcs8().decode(&info).unwrap();
    let key = key.as_any().downcast_ref::<ElGamalPrivateKey>().unwrap();
    let original = pair
        .private()
        .as_any()
        .downcast_ref::<ElGamalPrivateKey>()
        .unwrap();
    assert_eq!(key.x(), original.x());
    assert_eq!(asn1.pkcs8().encode(key).unwrap(), info);
}

// The keys read back still encrypt and decrypt together
#[test]
fn keys_read_back_encrypt_and_decrypt_with_each_other() {
    let asn1 = asn1();
    let pair = pair();
    let public = asn1
        .spki()
        .decode(&asn1.spki().encode(pair.public()).unwrap())
        .unwrap();
    let private = asn1
        .pkcs8()
        .decode(&asn1.pkcs8().encode(pair.private()).unwrap())
        .unwrap();

    let algo = DefaultAlgoBuilder::default().build();
    let name = "ELGAMAL//OAEPPADDING";
    let sealed = algo
        .cipher()
        .encrypt_by_name(name, public.as_ref(), b"attack at dawn")
        .unwrap();
    let opened = algo
        .cipher()
        .decrypt_by_name(name, private.as_ref(), &sealed)
        .unwrap();
    assert_eq!(opened, b"attack at dawn");
}

// The parameters are required, as Bouncy Castle's factories read them
#[test]
fn an_elgamal_key_without_its_parameters_is_invalid() {
    let asn1 = asn1();
    let pair = pair();
    let oid = "1.3.14.7.2.1.1".parse().unwrap();

    let spki = asn1.spki().encode(pair.public()).unwrap();
    let bare = SubjectPublicKeyInfo::new(
        AlgorithmIdentifier::new(oid),
        spki.subject_public_key().clone(),
    );
    assert!(matches!(
        asn1.spki().decode(&bare),
        Err(AlgoAsn1Error::InvalidPublicKey)
    ));

    let info = asn1.pkcs8().encode(pair.private()).unwrap();
    let bare = PrivateKeyInfo::new(
        AlgorithmIdentifier::new("1.3.14.7.2.1.1".parse().unwrap()),
        Asn1OctetString::new(info.private_key().as_bytes()),
    );
    assert!(matches!(
        asn1.pkcs8().decode(&bare),
        Err(AlgoAsn1Error::InvalidPrivateKey)
    ));
}
