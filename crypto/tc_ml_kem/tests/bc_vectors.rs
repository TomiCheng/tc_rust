//! ML-KEM：以 Bouncy Castle 由固定 seed 與 m 算出的向量（三組參數各四組；後兩組的 seed 使矩陣 A
//! 有一格要多擠一個 SHAKE128 區塊）比對金鑰、密文、共享秘密與隱式拒絕；隨機往返；金鑰檢查；
//! 以及錯誤。

use core::convert::Infallible;
use rand_core::{TryCryptoRng, TryRng};
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_kem::{KemDecapsulator, KemEncapsulator, KemInit};
use tc_ml_kem::{
    MlKemDecapsulator, MlKemEncapsulator, MlKemError, MlKemKeyGenerationParams,
    MlKemKeyPairGenerator, MlKemParameters, MlKemPrivateKey, MlKemPublicKey,
};

const SETS: [(MlKemParameters, &str); 3] = [
    (
        MlKemParameters::ML_KEM_512,
        include_str!("data/ml_kem_512.txt"),
    ),
    (
        MlKemParameters::ML_KEM_768,
        include_str!("data/ml_kem_768.txt"),
    ),
    (
        MlKemParameters::ML_KEM_1024,
        include_str!("data/ml_kem_1024.txt"),
    ),
];

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// 一組向量的欄位。
fn field<'a>(entry: &'a str, name: &str) -> &'a str {
    entry
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(" = "))
        .unwrap()
}

/// 依序給出 `data` 的亂數來源，BC 測試以它固定 m。
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
fn keys_ciphertexts_and_secrets_match_bouncy_castle_for_every_parameter_set() {
    for (params, data) in SETS {
        for entry in data.split("\n\n").filter(|entry| !entry.trim().is_empty()) {
            let seed: [u8; 64] = bytes(field(entry, "seed")).try_into().unwrap();
            let private_key = MlKemPrivateKey::from_seed(params, seed);
            assert_eq!(
                private_key.encoding(),
                &bytes(field(entry, "dk"))[..],
                "{params} dk"
            );
            let public_key = private_key.public_key();
            assert_eq!(
                public_key.encoding(),
                &bytes(field(entry, "ek"))[..],
                "{params} ek"
            );

            let mut sender = MlKemEncapsulator::new(params, Fixed(bytes(field(entry, "m"))));
            sender.init(&public_key).unwrap();
            let mut ciphertext = vec![0; sender.encapsulation_length()];
            let mut secret = [0; 32];
            sender.encapsulate(&mut ciphertext, &mut secret).unwrap();
            assert_eq!(ciphertext, bytes(field(entry, "ct")), "{params} ct");
            assert_eq!(secret[..], bytes(field(entry, "ss"))[..], "{params} ss");

            let mut receiver = MlKemDecapsulator::new(params);
            receiver.init(&private_key).unwrap();
            let mut recovered = [0; 32];
            receiver.decapsulate(&ciphertext, &mut recovered).unwrap();
            assert_eq!(recovered, secret, "{params} decapsulation");

            // 竄改一個位元組：得到 BC 算出的隱式拒絕值，而不是錯誤。
            let index: usize = field(entry, "bad").parse().unwrap();
            ciphertext[index] ^= 1;
            receiver.decapsulate(&ciphertext, &mut recovered).unwrap();
            assert_eq!(
                recovered[..],
                bytes(field(entry, "rejected"))[..],
                "{params} rejection"
            );
        }
    }
}

#[test]
fn random_key_pairs_round_trip_and_a_key_from_its_encoding_works_too() {
    for (params, _) in SETS {
        let mut rng = rand::rng();
        let mut generator = MlKemKeyPairGenerator::new();
        generator
            .init(MlKemKeyGenerationParams::new(params, &mut rng))
            .unwrap();
        let (public_key, private_key) = generator.generate_key_pair().unwrap();
        assert_eq!(public_key.encoding().len(), params.public_key_length());
        assert_eq!(private_key.encoding().len(), params.private_key_length());

        let mut sender = MlKemEncapsulator::new(params, rand::rng());
        sender.init(&public_key).unwrap();
        let mut ciphertext = vec![0; params.encapsulation_length()];
        let mut secret = [0; 32];
        sender.encapsulate(&mut ciphertext, &mut secret).unwrap();

        let decoded = MlKemPrivateKey::from_encoding(params, private_key.encoding().to_vec());
        assert!(decoded.seed().is_none());
        let mut receiver = MlKemDecapsulator::new(params);
        receiver.init(&decoded).unwrap();
        let mut recovered = [0; 32];
        receiver.decapsulate(&ciphertext, &mut recovered).unwrap();
        assert_eq!(recovered, secret);
    }
}

#[test]
fn keys_that_fail_the_fips_203_checks_are_refused() {
    let params = MlKemParameters::ML_KEM_512;
    let private_key = MlKemPrivateKey::from_seed(params, [7; 64]);
    let mut ek = private_key.public_key().encoding().to_vec();
    // 第一個係數設成 0xFFF，不小於 q。
    ek[0] = 0xFF;
    ek[1] |= 0x0F;
    assert_eq!(
        MlKemPublicKey::from_encoding(params, ek).validate(),
        Err(MlKemError::InvalidPublicKey)
    );
    assert_eq!(
        MlKemPublicKey::from_encoding(params, vec![0; 10]).validate(),
        Err(MlKemError::InvalidKeyLength)
    );

    let mut dk = private_key.encoding().to_vec();
    let h = dk.len() - 64;
    dk[h] ^= 1;
    assert_eq!(
        MlKemPrivateKey::from_encoding(params, dk).validate(),
        Err(MlKemError::InvalidPrivateKey)
    );
}

#[test]
fn errors_are_reported() {
    let params = MlKemParameters::ML_KEM_768;
    let private_key = MlKemPrivateKey::from_seed(params, [9; 64]);
    let public_key = private_key.public_key();

    let mut sender = MlKemEncapsulator::new(params, rand::rng());
    assert_eq!(
        sender.encapsulate(&mut [0; 1088], &mut [0; 32]),
        Err(MlKemError::NotInitialized)
    );
    let other = MlKemPrivateKey::from_seed(MlKemParameters::ML_KEM_512, [9; 64]);
    assert_eq!(
        sender.init(&other.public_key()),
        Err(MlKemError::ParameterMismatch)
    );
    sender.init(&public_key).unwrap();
    assert_eq!(
        sender.encapsulate(&mut [0; 1087], &mut [0; 32]),
        Err(MlKemError::InvalidEncapsulationLength)
    );
    assert_eq!(
        sender.encapsulate(&mut [0; 1088], &mut [0; 31]),
        Err(MlKemError::InvalidSecretLength)
    );

    let mut receiver = MlKemDecapsulator::new(params);
    assert_eq!(
        receiver.decapsulate(&[0; 1088], &mut [0; 32]),
        Err(MlKemError::NotInitialized)
    );
    assert_eq!(receiver.init(&other), Err(MlKemError::ParameterMismatch));
    receiver.init(&private_key).unwrap();
    assert_eq!(
        receiver.decapsulate(&[0; 1089], &mut [0; 32]),
        Err(MlKemError::InvalidEncapsulationLength)
    );
}
