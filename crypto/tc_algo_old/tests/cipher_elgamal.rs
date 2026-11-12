#![cfg(feature = "elgamal")]

use std::sync::LazyLock;

use tc_algo_old::{
    Algo, AnyKeyParams, AnyParams, AnyPrivateKey, AnyPublicKey, CipherDirection, CipherEntry,
    ErrorKind, SecretKey,
};

use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_elgamal::{
    ElGamalKeyGenerationParams, ElGamalKeyPairGenerator, ElGamalParameters, ElGamalPrivateKey,
    ElGamalPublicKey,
};

// One instance for the whole file, so that its tables are built once
#[allow(
    dead_code,
    reason = "unused when the features of the tests here are off"
)]
static ALGO: LazyLock<Algo> = LazyLock::new(Algo::new);

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

// The 2048-bit MODP group of RFC 3526 with g = 2, one key pair for every test
static KEYS: LazyLock<(ElGamalPublicKey, ElGamalPrivateKey)> = LazyLock::new(|| {
    let p = hex(
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74\
         020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437\
         4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed\
         ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05\
         98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb\
         9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b\
         e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718\
         3995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff",
    );
    let params = ElGamalParameters::new(
        PaddedBigUint::from_be(&p).unwrap(),
        PaddedBigUint::from(2u8),
    );
    let mut rng = rand::rng();
    let mut generator = ElGamalKeyPairGenerator::new();
    generator
        .init(ElGamalKeyGenerationParams::new(params, &mut rng))
        .unwrap();
    generator.generate_key_pair().unwrap()
});

fn public() -> AnyParams {
    AnyParams::new(AnyKeyParams::Public(AnyPublicKey::ElGamal(KEYS.0.clone())))
}

fn private() -> AnyParams {
    AnyParams::new(AnyKeyParams::Private(AnyPrivateKey::ElGamal(
        KEYS.1.clone(),
    )))
}

fn elgamal_entries() -> impl Iterator<Item = &'static CipherEntry> {
    ALGO.cipher()
        .algorithms()
        .filter(|entry| entry.name().starts_with("ELGAMAL/"))
}

#[test]
fn every_padding_decrypts_with_the_private_key_what_the_public_key_encrypts() {
    for entry in elgamal_entries() {
        let ciphertext = ALGO
            .cipher()
            .encrypt(entry.name(), &public(), b"attack at dawn")
            .unwrap();
        // Gamma and phi, each as long as p
        assert_eq!(ciphertext.len(), 512, "{}", entry.name());
        let plaintext = ALGO
            .cipher()
            .decrypt(entry.name(), &private(), &ciphertext)
            .unwrap();
        // ElGamal without padding gives the number back, without its leading zeros
        assert!(plaintext.ends_with(b"attack at dawn"), "{}", entry.name());
    }
}

#[test]
fn encrypting_twice_gives_two_ciphertexts() {
    let first = ALGO
        .cipher()
        .encrypt("ELGAMAL/NONE/PKCS1PADDING", &public(), b"message")
        .unwrap();
    let second = ALGO
        .cipher()
        .encrypt("ELGAMAL/NONE/PKCS1PADDING", &public(), b"message")
        .unwrap();
    assert_ne!(first, second);
}

#[test]
fn the_public_key_only_encrypts_and_the_private_key_only_decrypts() {
    for (direction, params) in [
        (CipherDirection::Decrypt, public()),
        (CipherDirection::Encrypt, private()),
    ] {
        let mut cipher = ALGO
            .cipher()
            .get_by_name("ELGAMAL/NONE/PKCS1PADDING")
            .unwrap();
        let error = cipher.init(direction, &params).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}

#[test]
fn a_changed_ciphertext_fails_alike_under_pkcs1_and_oaep() {
    for name in [
        "ELGAMAL/NONE/PKCS1PADDING",
        "ELGAMAL/NONE/OAEPWITHSHA256ANDMGF1PADDING",
    ] {
        let mut ciphertext = ALGO.cipher().encrypt(name, &public(), b"message").unwrap();
        ciphertext[400] ^= 1;
        let error = ALGO
            .cipher()
            .decrypt(name, &private(), &ciphertext)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidCiphertext, "{name}");
    }
}

#[test]
fn a_message_longer_than_the_padding_leaves_room_for_is_a_data_length_error() {
    // The input block is 255 bytes, a byte short of p, less the other 10 of PKCS#1 v1.5
    let name = "ELGAMAL/NONE/PKCS1PADDING";
    let error = ALGO
        .cipher()
        .encrypt(name, &public(), &[1; 246])
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::DataLength);
    assert!(ALGO.cipher().encrypt(name, &public(), &[1; 245]).is_ok());
}

#[test]
fn names_follow_bouncy_castle_and_come_back_canonical() {
    for (name, canonical) in [
        ("ElGamal", "ELGAMAL/NONE/NOPADDING"),
        ("elgamal/ecb/pkcs1padding", "ELGAMAL/NONE/PKCS1PADDING"),
        ("ELGAMAL//OAEP", "ELGAMAL/NONE/OAEPWITHSHA1ANDMGF1PADDING"),
    ] {
        let cipher = ALGO.cipher().get_by_name(name).unwrap();
        assert_eq!(cipher.entry().name(), canonical, "{name}");
    }
}

#[cfg(feature = "rsa-iso9796")]
#[test]
fn iso_9796_1_is_an_unknown_cipher_for_elgamal() {
    let error = ALGO
        .cipher()
        .get_by_name("ELGAMAL/NONE/ISO9796-1PADDING")
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnknownCipher);
}

#[test]
fn the_table_has_elgamal_with_each_of_its_paddings() {
    let md5 = usize::from(cfg!(feature = "md5"));
    assert_eq!(elgamal_entries().count(), 8 + md5);
    assert!(elgamal_entries().all(|entry| entry.oids().is_empty()));
}

#[test]
fn elgamal_refuses_a_secret_key_and_an_operation_field() {
    let secret = AnyParams::new(AnyKeyParams::Secret(SecretKey::new(vec![1; 16])));
    let mut with_iv = public();
    with_iv.op.iv = Some(vec![0; 16]);
    for params in [secret, with_iv] {
        let mut cipher = ALGO
            .cipher()
            .get_by_name("ELGAMAL/NONE/PKCS1PADDING")
            .unwrap();
        let error = cipher.init(CipherDirection::Encrypt, &params).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}
