//! `NaccacheSternKeyPairGenerator`：BC 測試的 768 位元、30 個小質數的金鑰，以及參數檢查。

use tc_asym_cipher::{
    AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection, KeyPairGenerator,
    KeyPairGeneratorInit,
};
use tc_bigint::BigUint;
use tc_naccache_stern::{
    NaccacheSternEngine, NaccacheSternError, NaccacheSternKeyGenerationParams,
    NaccacheSternKeyPairGenerator,
};

/// 產生金鑰並檢查各部分吻合，再以前幾個位元組加解密一次。
fn generate_and_round_trip(strength: u32, count: usize) {
    let mut rng = rand::rng();
    let mut generator = NaccacheSternKeyPairGenerator::new();
    generator
        .init(NaccacheSternKeyGenerationParams::new(
            &mut rng, strength, 8, count,
        ))
        .unwrap();
    let (public_key, private_key) = generator.generate_key_pair().unwrap();

    assert!(BigUint::from(public_key.n().clone()).bits() >= strength);
    let mut primes = private_key.small_primes().to_vec();
    primes.sort_unstable();
    assert_eq!(primes[..3], [3, 5, 7]);
    assert_eq!(primes.len(), count);
    let sigma = primes
        .iter()
        .fold(BigUint::from(1u8), |sigma, &p| sigma * BigUint::from(p));
    assert_eq!(public_key.lower_sigma_bound(), sigma.bits());

    let message = b"Now is the time";
    let mut encryptor = NaccacheSternEngine::new();
    encryptor
        .init(CipherDirection::Encrypt, &public_key)
        .unwrap();
    let input = &message[..encryptor.input_block_size().min(message.len())];
    let mut ciphertext = vec![0; encryptor.output_block_size()];
    encryptor.process_block(input, &mut ciphertext).unwrap();

    let mut decryptor = NaccacheSternEngine::new();
    decryptor
        .init(CipherDirection::Decrypt, &private_key)
        .unwrap();
    let mut plaintext = vec![0; decryptor.output_block_size()];
    let length = decryptor
        .process_block(&ciphertext, &mut plaintext)
        .unwrap();
    assert!(plaintext[..length].ends_with(input));
}

#[test]
fn a_256_bit_key_round_trips_and_its_parts_fit_together() {
    generate_and_round_trip(256, 30);
}

/// BC `NaccacheSternTest` 的參數。release 約 1.5 秒，debug 一分鐘以上，所以預設略過：
/// `cargo test --release -p tc_naccache_stern -- --ignored`。
#[test]
#[ignore = "slow in debug builds; run with --release -- --ignored"]
fn a_768_bit_key_from_the_bouncy_castle_test_round_trips() {
    generate_and_round_trip(768, 30);
}

#[test]
fn init_checks_the_generation_parameters() {
    let mut rng = rand::rng();
    for (count, error) in [
        (29, NaccacheSternError::InvalidSmallPrimeCount),
        (28, NaccacheSternError::InvalidSmallPrimeCount),
        (102, NaccacheSternError::InvalidSmallPrimeCount),
    ] {
        assert_eq!(
            NaccacheSternKeyPairGenerator::new().init(NaccacheSternKeyGenerationParams::new(
                &mut rng, 768, 8, count
            )),
            Err(error),
            "{count} small primes"
        );
    }
    assert_eq!(
        NaccacheSternKeyPairGenerator::new()
            .init(NaccacheSternKeyGenerationParams::new(&mut rng, 768, 0, 30)),
        Err(NaccacheSternError::InvalidCertainty)
    );
    assert_eq!(
        NaccacheSternKeyPairGenerator::new()
            .init(NaccacheSternKeyGenerationParams::new(&mut rng, 200, 8, 30)),
        Err(NaccacheSternError::StrengthTooSmall)
    );
    assert_eq!(
        NaccacheSternKeyPairGenerator::new()
            .generate_key_pair()
            .err(),
        Some(NaccacheSternError::NotInitialized)
    );
}
