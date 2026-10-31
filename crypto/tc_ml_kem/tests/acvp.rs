//! ML-KEM：NIST ACVP-Server 的 FIPS 203 向量（vsId 42）。金鑰產生、封裝各 75 組，解封裝 30 組
//! （一半是竄改過的密文，取隱式拒絕值），封裝金鑰與解封裝金鑰的檢查共 60 組。輸出較大的
//! ek、dk 與密文以 SHA-256 比對。

use core::convert::Infallible;
use rand_core::{TryCryptoRng, TryRng};
use tc_digest::Digest;
use tc_kem::{KemDecapsulator, KemEncapsulator, KemInit};
use tc_ml_kem::{
    MlKemDecapsulator, MlKemEncapsulator, MlKemParameters, MlKemPrivateKey, MlKemPublicKey,
};
use tc_sha::Sha256Digest;

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn sha256(data: &[u8]) -> Vec<u8> {
    let mut digest = Sha256Digest::new();
    digest.update(data);
    let mut hash = vec![0; 32];
    digest.do_final(&mut hash);
    hash
}

fn params(set: &str) -> MlKemParameters {
    match set {
        "512" => MlKemParameters::ML_KEM_512,
        "768" => MlKemParameters::ML_KEM_768,
        _ => MlKemParameters::ML_KEM_1024,
    }
}

/// 每一行的欄位，略過註解。
fn rows(data: &str) -> impl Iterator<Item = Vec<&str>> {
    data.lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .map(|line| line.split(' ').collect())
}

/// 依序給出 m 的亂數來源。
struct Fixed(Vec<u8>);

impl TryRng for Fixed {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        unreachable!("ML-KEM reads whole byte strings")
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        unreachable!("ML-KEM reads whole byte strings")
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Infallible> {
        output.copy_from_slice(&self.0[..output.len()]);
        self.0.drain(..output.len());
        Ok(())
    }
}

impl TryCryptoRng for Fixed {}

#[test]
fn the_75_nist_key_generation_vectors_match() {
    let mut count = 0;
    for row in rows(include_str!("data/acvp_keygen.txt")) {
        let [set, d, z, ek, dk] = row[..] else {
            panic!("malformed row")
        };
        let seed: [u8; 64] = [bytes(d), bytes(z)].concat().try_into().unwrap();
        let private_key = MlKemPrivateKey::from_seed(params(set), seed);
        assert_eq!(
            sha256(private_key.encoding()),
            bytes(dk),
            "dk of ML-KEM-{set}"
        );
        assert_eq!(
            sha256(private_key.public_key().encoding()),
            bytes(ek),
            "ek of ML-KEM-{set}"
        );
        count += 1;
    }
    assert_eq!(count, 75);
}

#[test]
fn the_75_nist_encapsulation_vectors_match() {
    let mut count = 0;
    for row in rows(include_str!("data/acvp_encapsulation.txt")) {
        let [set, ek, m, c, k] = row[..] else {
            panic!("malformed row")
        };
        let params = params(set);
        let mut sender = MlKemEncapsulator::new(params, Fixed(bytes(m)));
        sender
            .init(&MlKemPublicKey::from_encoding(params, bytes(ek)))
            .unwrap();
        let mut ciphertext = vec![0; params.encapsulation_length()];
        let mut secret = [0; 32];
        sender.encapsulate(&mut ciphertext, &mut secret).unwrap();
        assert_eq!(sha256(&ciphertext), bytes(c), "c of ML-KEM-{set}");
        assert_eq!(secret[..], bytes(k)[..], "k of ML-KEM-{set}");
        count += 1;
    }
    assert_eq!(count, 75);
}

#[test]
fn the_30_nist_decapsulation_vectors_match_including_implicit_rejection() {
    let (mut valid, mut rejected) = (0, 0);
    for row in rows(include_str!("data/acvp_decapsulation.txt")) {
        let [set, is_valid, dk, c, k] = row[..] else {
            panic!("malformed row")
        };
        let params = params(set);
        let mut receiver = MlKemDecapsulator::new(params);
        receiver
            .init(&MlKemPrivateKey::from_encoding(params, bytes(dk)))
            .unwrap();
        let mut secret = [0; 32];
        receiver.decapsulate(&bytes(c), &mut secret).unwrap();
        assert_eq!(secret[..], bytes(k)[..], "k of ML-KEM-{set}");
        if is_valid == "1" {
            valid += 1;
        } else {
            rejected += 1;
        }
    }
    assert_eq!((valid, rejected), (15, 15));
}

#[test]
fn the_60_nist_key_checks_accept_and_refuse_as_expected() {
    let mut count = 0;
    for row in rows(include_str!("data/acvp_key_check.txt")) {
        let [set, kind, passed, key] = row[..] else {
            panic!("malformed row")
        };
        let params = params(set);
        let ok = match kind {
            "ek" => MlKemPublicKey::from_encoding(params, bytes(key)).validate(),
            _ => MlKemPrivateKey::from_encoding(params, bytes(key)).validate(),
        }
        .is_ok();
        assert_eq!(ok, passed == "1", "{kind} check of ML-KEM-{set}");
        count += 1;
    }
    assert_eq!(count, 60);
}
