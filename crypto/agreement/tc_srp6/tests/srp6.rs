//! SRP-6a：Bouncy Castle `Srp6Test` 的互通與錯誤情況（RFC 5054 附錄 B 的向量在 crate 內的
//! 單元測試），加上證明不符、步驟順序與標準群組。

use rand::rngs::ThreadRng;
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_dh_key::DhParametersGenerator;
use tc_sha::Sha256Digest;
use tc_srp6::standard_groups::{
    rfc5054_1024, rfc5054_1536, rfc5054_2048, rfc5054_3072, rfc5054_4096, rfc5054_6144,
    rfc5054_8192,
};
use tc_srp6::{Srp6Client, Srp6Error, Srp6GroupParameters, Srp6Server, Srp6VerifierGenerator};

const IDENTITY: &[u8] = b"username";
const PASSWORD: &[u8] = b"password";

fn salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    rand::fill(&mut salt);
    salt
}

fn verifier(group: &Srp6GroupParameters, salt: &[u8], password: &[u8]) -> PaddedBigUint {
    let mut generator = Srp6VerifierGenerator::new(Sha256Digest::new());
    generator.init(group).unwrap();
    generator
        .generate_verifier(salt, IDENTITY, password)
        .unwrap()
}

fn client(group: &Srp6GroupParameters) -> Srp6Client<Sha256Digest, ThreadRng> {
    let mut client = Srp6Client::new(Sha256Digest::new(), rand::rng());
    client.init(group).unwrap();
    client
}

fn server(group: &Srp6GroupParameters, v: &PaddedBigUint) -> Srp6Server<Sha256Digest, ThreadRng> {
    let mut server = Srp6Server::new(Sha256Digest::new(), rand::rng());
    server.init(group, v).unwrap();
    server
}

/// BC 的 `ImplTestMutualVerification`，再把證明與工作階段金鑰也走完。
fn mutual_verification(group: &Srp6GroupParameters) {
    let salt = salt();
    let v = verifier(group, &salt, PASSWORD);
    let mut client = client(group);
    let mut server = server(group, &v);

    let a = client
        .generate_client_credentials(&salt, IDENTITY, PASSWORD)
        .unwrap();
    let b = server.generate_server_credentials().unwrap();
    assert_eq!(
        client.calculate_secret(&b).unwrap(),
        server.calculate_secret(&a).unwrap(),
        "client and server calculated different secrets"
    );

    let m1 = client.calculate_client_evidence_message().unwrap();
    assert!(server.verify_client_evidence_message(&m1).unwrap());
    let m2 = server.calculate_server_evidence_message().unwrap();
    assert!(client.verify_server_evidence_message(&m2).unwrap());
    assert_eq!(
        client.calculate_session_key().unwrap(),
        server.calculate_session_key().unwrap()
    );
}

#[test]
fn client_and_server_agree_over_the_rfc_5054_1024_bit_group() {
    mutual_verification(&rfc5054_1024());
}

#[test]
fn client_and_server_agree_over_generated_safe_prime_groups() {
    for bits in [256, 384, 512] {
        let mut rng = rand::rng();
        let mut generator = DhParametersGenerator::new();
        generator.init(bits, 25, &mut rng).unwrap();
        let params = generator.generate_parameters().unwrap();
        mutual_verification(&Srp6GroupParameters::new(
            params.p().clone(),
            params.g().clone(),
        ));
    }
}

#[test]
fn the_client_rejects_a_server_value_divisible_by_n() {
    let group = rfc5054_1024();
    let mut client = client(&group);
    client
        .generate_client_credentials(&salt(), IDENTITY, PASSWORD)
        .unwrap();
    for b in [PaddedBigUint::from(0u8), group.n().clone()] {
        assert_eq!(
            client.calculate_secret(&b),
            Err(Srp6Error::InvalidPublicValue)
        );
    }
}

#[test]
fn the_server_rejects_a_client_value_divisible_by_n() {
    let group = rfc5054_1024();
    let salt = salt();
    let mut server = server(&group, &verifier(&group, &salt, PASSWORD));
    server.generate_server_credentials().unwrap();
    for a in [PaddedBigUint::from(0u8), group.n().clone()] {
        assert_eq!(
            server.calculate_secret(&a),
            Err(Srp6Error::InvalidPublicValue)
        );
    }
}

#[test]
fn a_wrong_password_fails_the_client_evidence_and_leaves_no_session_key() {
    let group = rfc5054_1024();
    let salt = salt();
    let mut client = client(&group);
    let mut server = server(&group, &verifier(&group, &salt, PASSWORD));

    let a = client
        .generate_client_credentials(&salt, IDENTITY, b"wrong password")
        .unwrap();
    let b = server.generate_server_credentials().unwrap();
    client.calculate_secret(&b).unwrap();
    server.calculate_secret(&a).unwrap();

    let m1 = client.calculate_client_evidence_message().unwrap();
    assert!(!server.verify_client_evidence_message(&m1).unwrap());
    assert_eq!(
        server.calculate_server_evidence_message(),
        Err(Srp6Error::MissingValues)
    );
    assert_eq!(
        server.calculate_session_key(),
        Err(Srp6Error::MissingValues)
    );
}

#[test]
fn a_forged_server_evidence_is_rejected_and_leaves_no_session_key() {
    let group = rfc5054_1024();
    let salt = salt();
    let mut client = client(&group);
    let mut server = server(&group, &verifier(&group, &salt, PASSWORD));

    let a = client
        .generate_client_credentials(&salt, IDENTITY, PASSWORD)
        .unwrap();
    let b = server.generate_server_credentials().unwrap();
    client.calculate_secret(&b).unwrap();
    server.calculate_secret(&a).unwrap();
    let m1 = client.calculate_client_evidence_message().unwrap();
    assert!(server.verify_client_evidence_message(&m1).unwrap());

    let mut m2 = server.calculate_server_evidence_message().unwrap();
    m2[0] ^= 1;
    assert!(!client.verify_server_evidence_message(&m2).unwrap());
    assert!(!client.verify_server_evidence_message(&[0; 33]).unwrap());
    assert_eq!(
        client.calculate_session_key(),
        Err(Srp6Error::MissingValues)
    );
}

#[test]
fn every_step_needs_init_and_the_steps_before_it() {
    let group = rfc5054_1024();
    let mut client = Srp6Client::new(Sha256Digest::new(), rand::rng());
    assert_eq!(
        client.generate_client_credentials(&[], IDENTITY, PASSWORD),
        Err(Srp6Error::NotInitialized)
    );
    client.init(&group).unwrap();
    assert_eq!(
        client.calculate_secret(group.g()),
        Err(Srp6Error::MissingValues)
    );
    assert_eq!(
        client.calculate_client_evidence_message(),
        Err(Srp6Error::MissingValues)
    );
    assert_eq!(
        client.verify_server_evidence_message(&[]),
        Err(Srp6Error::MissingValues)
    );

    let mut server = Srp6Server::new(Sha256Digest::new(), rand::rng());
    assert_eq!(
        server.generate_server_credentials(),
        Err(Srp6Error::NotInitialized)
    );
    server.init(&group, group.g()).unwrap();
    assert_eq!(
        server.calculate_secret(group.g()),
        Err(Srp6Error::MissingValues)
    );
    assert_eq!(
        server.verify_client_evidence_message(&[]),
        Err(Srp6Error::MissingValues)
    );

    let mut generator = Srp6VerifierGenerator::new(Sha256Digest::new());
    assert_eq!(
        generator.generate_verifier(&[], IDENTITY, PASSWORD),
        Err(Srp6Error::NotInitialized)
    );
}

#[test]
fn init_rejects_an_even_modulus_and_a_generator_out_of_range() {
    let n = rfc5054_1024().n().clone();
    let even = &n + 1u32;
    for group in [
        Srp6GroupParameters::new(even, PaddedBigUint::from(2u8)),
        Srp6GroupParameters::new(PaddedBigUint::from(3u8), PaddedBigUint::from(2u8)),
        Srp6GroupParameters::new(n.clone(), PaddedBigUint::from(1u8)),
        Srp6GroupParameters::new(n.clone(), &n - 1u32),
    ] {
        let mut generator = Srp6VerifierGenerator::new(Sha256Digest::new());
        assert_eq!(generator.init(&group), Err(Srp6Error::InvalidGroup));
    }
}

#[test]
fn every_standard_group_has_the_size_its_name_gives_and_passes_init() {
    for (bits, group, g) in [
        (1024, rfc5054_1024(), 2u8),
        (1536, rfc5054_1536(), 2),
        (2048, rfc5054_2048(), 2),
        (3072, rfc5054_3072(), 5),
        (4096, rfc5054_4096(), 5),
        (6144, rfc5054_6144(), 5),
        (8192, rfc5054_8192(), 19),
    ] {
        assert_eq!(group.n().bits(), bits);
        assert_eq!(*group.g(), PaddedBigUint::from(g));
        let mut generator = Srp6VerifierGenerator::new(Sha256Digest::new());
        generator.init(&group).unwrap();
    }
}

#[test]
fn the_session_key_is_the_digest_of_the_padded_secret() {
    let group = rfc5054_1024();
    let salt = salt();
    let mut client = client(&group);
    let mut server = server(&group, &verifier(&group, &salt, PASSWORD));
    let a = client
        .generate_client_credentials(&salt, IDENTITY, PASSWORD)
        .unwrap();
    let b = server.generate_server_credentials().unwrap();
    let s = client.calculate_secret(&b).unwrap();
    server.calculate_secret(&a).unwrap();
    let m1 = client.calculate_client_evidence_message().unwrap();
    server.verify_client_evidence_message(&m1).unwrap();
    let m2 = server.calculate_server_evidence_message().unwrap();
    client.verify_server_evidence_message(&m2).unwrap();

    let mut padded = vec![0u8; 128];
    let bytes = ArrayEncoding::<u8>::to_be(&s);
    padded[128 - bytes.len()..].copy_from_slice(&bytes);
    let mut digest = Sha256Digest::new();
    let expected = tc_srp6::utilities::calculate_key(&mut digest, group.n(), &s);
    assert_eq!(client.calculate_session_key().unwrap(), expected);
    let mut sha = Sha256Digest::new();
    let mut direct = [0u8; 32];
    tc_digest::Digest::update(&mut sha, &padded);
    tc_digest::Digest::do_final(&mut sha, &mut direct);
    assert_eq!(expected, direct);
}
