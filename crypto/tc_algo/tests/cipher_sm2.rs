#![cfg(feature = "sm2")]

use std::sync::LazyLock;

use tc_algo::ErrorKind;
use tc_algo::cipher::{self, CipherDirection};
use tc_algo::params::{
    AnyEcPrivateKey, AnyEcPublicKey, AnyKeyParams, AnyParams, AnyPrivateKey, AnyPublicKey,
    SecretKey,
};
use tc_asym_cipher::{AsymmetricBlockCipherInit, KeyPairGenerator, KeyPairGeneratorInit};
use tc_ec_key::{EcKeyGenerationParams, EcKeyPairGenerator, EcPrivateKey, EcPublicKey};
use tc_fp_custom::named_curves::SM2P256V1;
use tc_fp_custom::{SM2P256V1FieldElement, SecPCtCurve};
use tc_sm2::{Sm2Engine, Sm2Mode};

type Curve = &'static SecPCtCurve<SM2P256V1FieldElement>;

// A key points into its curve, so the curve lives for the whole program, with one key pair for
// every test
static CURVE: LazyLock<SecPCtCurve<SM2P256V1FieldElement>> = LazyLock::new(|| SM2P256V1.ct_curve());

static KEYS: LazyLock<(EcPublicKey<Curve>, EcPrivateKey<Curve>)> = LazyLock::new(|| {
    let mut rng = rand::rng();
    let mut generator = EcKeyPairGenerator::<Curve>::new();
    generator
        .init(EcKeyGenerationParams::new(
            SM2P256V1.ct_generator(&*CURVE),
            &mut rng,
        ))
        .unwrap();
    generator.generate_key_pair().unwrap()
});

fn public() -> AnyParams {
    let key = AnyEcPublicKey::Sm2p256v1(Box::new(KEYS.0.clone()));
    AnyParams::new(AnyKeyParams::Public(AnyPublicKey::Ec(key)))
}

fn private() -> AnyParams {
    let key = AnyEcPrivateKey::Sm2p256v1(Box::new(KEYS.1.clone()));
    AnyParams::new(AnyKeyParams::Private(AnyPrivateKey::Ec(key)))
}

// Decrypts with the engine itself, to check the order of the three parts
fn engine_decrypt(mode: Sm2Mode, ciphertext: &[u8]) -> Vec<u8> {
    let mut engine = Sm2Engine::<Curve, _>::new(mode, rand::rng());
    engine
        .init(tc_asym_cipher::CipherDirection::Decrypt, &KEYS.1)
        .unwrap();
    let mut output = vec![0; engine.output_size(ciphertext.len())];
    let written = engine.process_block(ciphertext, &mut output).unwrap();
    output.truncate(written);
    output
}

#[test]
fn each_mode_decrypts_with_the_private_key_what_the_public_key_encrypts() {
    for (name, mode) in [
        ("SM2/C1C2C3", Sm2Mode::C1C2C3),
        ("SM2/C1C3C2", Sm2Mode::C1C3C2),
    ] {
        for length in [1, 32, 100] {
            let message: Vec<u8> = (0..length).map(|i| i as u8).collect();
            let ciphertext = cipher::encrypt(name, &public(), &message).unwrap();
            // C1, an uncompressed point, then the message and an SM3 hash
            assert_eq!(ciphertext.len(), 65 + length + 32, "{name}");
            assert_eq!(engine_decrypt(mode, &ciphertext), message, "{name}");
            assert_eq!(
                cipher::decrypt(name, &private(), &ciphertext).unwrap(),
                message,
                "{name}"
            );
        }
    }
}

#[test]
fn the_two_orders_do_not_read_each_others_ciphertext() {
    let ciphertext = cipher::encrypt("SM2/C1C3C2", &public(), b"attack at dawn").unwrap();
    let error = cipher::decrypt("SM2/C1C2C3", &private(), &ciphertext).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidCiphertext);
}

#[test]
fn update_keeps_the_message_and_finalize_gives_the_whole_ciphertext() {
    let mut cipher = cipher::get_by_name("SM2").unwrap();
    cipher.init(CipherDirection::Encrypt, &public()).unwrap();
    assert!(cipher.update(b"attack ").unwrap().is_empty());
    assert!(cipher.update(b"at dawn").unwrap().is_empty());
    let ciphertext = cipher.finalize().unwrap();
    assert_eq!(
        cipher::decrypt("SM2", &private(), &ciphertext).unwrap(),
        b"attack at dawn"
    );
    // The next message goes under the same key with a new k
    assert!(cipher.update(b"attack at dawn").unwrap().is_empty());
    assert_ne!(cipher.finalize().unwrap(), ciphertext);
}

#[test]
fn a_changed_ciphertext_is_an_invalid_ciphertext() {
    let mut ciphertext = cipher::encrypt("SM2", &public(), b"attack at dawn").unwrap();
    ciphertext[70] ^= 1;
    let error = cipher::decrypt("SM2", &private(), &ciphertext).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidCiphertext);
}

#[test]
fn an_empty_message_or_too_short_a_ciphertext_is_a_data_length_error() {
    let error = cipher::encrypt("SM2", &public(), b"").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::DataLength);
    let error = cipher::decrypt("SM2", &private(), &[4; 96]).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::DataLength);
}

#[test]
fn the_public_key_only_encrypts_and_the_private_key_only_decrypts() {
    for (direction, params) in [
        (CipherDirection::Decrypt, public()),
        (CipherDirection::Encrypt, private()),
    ] {
        let mut cipher = cipher::get_by_name("SM2").unwrap();
        let error = cipher.init(direction, &params).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}

#[test]
fn sm2_refuses_a_key_off_its_curve_a_secret_key_and_an_operation_field() {
    let p256 = tc_fp_custom::named_curves::SECP256R1;
    static P256: LazyLock<SecPCtCurve<tc_fp_custom::SecP256R1FieldElement>> =
        LazyLock::new(|| tc_fp_custom::named_curves::SECP256R1.ct_curve());
    let g = p256.ct_generator(&*P256);
    let other = AnyEcPublicKey::Secp256r1(Box::new(EcPublicKey::new(g.clone(), &g).unwrap()));
    let mut with_iv = public();
    with_iv.op.iv = Some(vec![0; 16]);
    for params in [
        AnyParams::new(AnyKeyParams::Public(AnyPublicKey::Ec(other))),
        AnyParams::new(AnyKeyParams::Secret(SecretKey::new(vec![1; 16]))),
        with_iv,
    ] {
        let mut cipher = cipher::get_by_name("SM2").unwrap();
        let error = cipher.init(CipherDirection::Encrypt, &params).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}

#[test]
fn names_take_a_mode_but_no_padding() {
    for (name, canonical) in [
        ("SM2", "SM2/C1C2C3"),
        ("sm2/", "SM2/C1C2C3"),
        ("sm2/c1c3c2", "SM2/C1C3C2"),
    ] {
        let cipher = cipher::get_by_name(name).unwrap();
        assert_eq!(cipher.entry().name(), canonical, "{name}");
    }
    for name in ["SM2/NONE", "SM2/C1C3C2/NOPADDING", "SM2/C1C3C2/", "SM2//"] {
        let error = cipher::get_by_name(name).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnknownCipher, "{name}");
    }
}

#[test]
fn the_table_has_sm2_in_its_two_orders() {
    let names: Vec<&str> = cipher::algorithms()
        .map(|entry| entry.name())
        .filter(|name| name.starts_with("SM2/"))
        .collect();
    assert_eq!(names, ["SM2/C1C2C3", "SM2/C1C3C2"]);
}
