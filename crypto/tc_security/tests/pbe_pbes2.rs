//! PBES2：解開 OpenSSL 加密的 PKCS#8、產生的參數加解密往返，以及不支援的 KDF 與缺 IV 的加密方案。

#![cfg(all(feature = "pbe", feature = "aes", feature = "sha1", feature = "sha256"))]

use std::error::Error;

use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use tc_asn1::{Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};
use tc_asn1_pkcs::{EncryptedPrivateKeyInfo, Pbes2Params, Pkcs5Algorithm};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_security::pbe::Pbes2;
use tc_security::{AnyError, SecurityError, cipher};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// 沿著 source 往下找第一個 `E`。
fn source<E: Error + 'static>(error: &AnyError) -> Option<&E> {
    let mut source = error.source();
    while let Some(error) = source {
        if let Some(found) = error.downcast_ref() {
            return Some(found);
        }
        source = error.source();
    }
    None
}

/// OpenSSL 3.5 產生的 P-256 私鑰（PKCS#8）。
const PLAIN: &str = concat!(
    "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420e27f3682f93f80d7f35d7a3d",
    "381dae2bb409b3b5d240b487a8571299efaf91b1a1440342000498c8c2a2872e6787664c30a7dc573e253cac2c261556",
    "ed5b22598920cb3c25bec657770272b3e218a7a211ec1f5280062200949f8e3db03fd658f3cfcdccab62",
);

/// `openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 -iter 2048 -passout pass:password`。
const AES256_SHA256: &str = concat!(
    "3081f4305f06092a864886f70d01050d3052303106092a864886f70d01050c302404109720f2fe1c4e34713399cdc892",
    "ef838602020800300c06082a864886f70d02090500301d060960864801650304012a04101cbaa2e315e193a0fd4d80df",
    "af1a5829048190a905cdf2717d2f58698f5e5d08a7ff19ef70cb88e9b0539f1ef1027d2374409afc2f4920c4e328b6e6",
    "e6a2758b36714d4a2cc1ce0f599ead3ccd73de1b4e0074871077784a6d1d19616d64ad644a44846718cdc14de42a42c0",
    "8e6c5ac6b19c3dcd07d6bcc7fe717c804e48f90371a0781a2c8c9e981c5e057b794f4d91d9975eaa98a7a83b3a7caf7a",
    "686859fb0983ba",
);

/// `openssl pkcs8 -topk8 -v2 aes-128-cbc -v2prf hmacWithSHA1 -iter 1000 -passout pass:password`：
/// PRF 是預設值，沒有寫出來。
const AES128_SHA1: &str = concat!(
    "3081e6305106092a864886f70d01050d3044302306092a864886f70d01050c30160410be231e4a99c2760d2e46e0a5c9",
    "06e2a6020203e8301d06096086480165030401020410d7f108efaf92f65f2f85a5cdaba51b76048190ccabcd41ba2abf",
    "28f74e4f05e062fd8a449c5306e3c88977373e00db9a7e726b73d23e6c4831214a8c81e5f10b8b0d6bead0cd159e5adf",
    "2a8295f0cb3edb331586fe0808d312bef5624d5f6bdb97dc11f59b542be9fd460387b00e78c782150e071fbea1ea58af",
    "e66f50c207285cded5e580256a0ce037134b3c7752cf64297fffdbe2b72f5b0115209f8ef275d74f80",
);

fn pbes2_params(info: &EncryptedPrivateKeyInfo) -> Pbes2Params {
    let algorithm = info.encryption_algorithm();
    assert_eq!(algorithm.algorithm(), &Pkcs5Algorithm::PBES2.oid());
    let der = algorithm
        .parameters()
        .unwrap()
        .encode_to_vec(&EncodingOptions::DER)
        .unwrap();
    Pbes2Params::decode(&der, &DecodingOptions::default())
        .unwrap()
        .1
}

#[test]
fn openssl_pbes2_keys_decrypt_with_the_password() {
    for encrypted in [AES256_SHA256, AES128_SHA1] {
        let info = EncryptedPrivateKeyInfo::decode(&hex(encrypted), &DecodingOptions::default())
            .unwrap()
            .1;
        let pbes2 = Pbes2::from_params(&pbes2_params(&info)).unwrap();
        let params = pbes2.generate_cipher_params("password").unwrap();
        let mut cipher = pbes2.cipher();
        let plain =
            cipher::decrypt(&mut cipher, &params, info.encrypted_data().as_bytes()).unwrap();
        assert_eq!(plain, hex(PLAIN));

        let params = pbes2.generate_cipher_params("wrong password").unwrap();
        assert_ne!(
            cipher::decrypt(&mut cipher, &params, info.encrypted_data().as_bytes()).ok(),
            Some(hex(PLAIN))
        );
    }
}

#[test]
fn generated_parameters_encrypt_and_read_back_from_their_encoding() {
    let mut rng = UnwrapErr(SysRng);
    let pbes2 = Pbes2::generate(
        &"2.16.840.1.101.3.4.1.42".parse().unwrap(),
        &Pkcs5Algorithm::HMAC_WITH_SHA256.oid(),
        &[7; 16],
        2048,
        &mut rng,
    )
    .unwrap();
    let mut cipher = pbes2.cipher();
    let sealed = cipher::encrypt(
        &mut cipher,
        &pbes2.generate_cipher_params("password").unwrap(),
        b"secret key",
    )
    .unwrap();

    let der = pbes2.params().encode_to_vec(&EncodingOptions::DER).unwrap();
    let back = Pbes2Params::decode(&der, &DecodingOptions::default())
        .unwrap()
        .1;
    let back = Pbes2::from_params(&back).unwrap();
    let mut cipher = back.cipher();
    let params = back.generate_cipher_params("password").unwrap();
    assert_eq!(
        cipher::decrypt(&mut cipher, &params, &sealed).unwrap(),
        b"secret key"
    );
}

#[test]
fn an_unknown_kdf_and_a_scheme_without_an_iv_are_refused() {
    let info = EncryptedPrivateKeyInfo::decode(&hex(AES256_SHA256), &DecodingOptions::default())
        .unwrap()
        .1;
    let params = pbes2_params(&info);

    let scrypt = Pbes2Params::new(
        AlgorithmIdentifier::new("1.3.6.1.4.1.11591.4.11".parse().unwrap()),
        params.encryption_scheme().clone(),
    );
    let Err(error) = Pbes2::from_params(&scrypt) else {
        panic!("scrypt is not PBKDF2");
    };
    assert_eq!(
        source::<SecurityError>(&error),
        Some(&SecurityError::UnknownPbe)
    );

    for scheme in [
        AlgorithmIdentifier::new(params.encryption_scheme().algorithm().clone()),
        AlgorithmIdentifier::with_null(params.encryption_scheme().algorithm().clone()),
    ] {
        let no_iv = Pbes2Params::new(params.key_derivation_func().clone(), scheme);
        let Err(error) = Pbes2::from_params(&no_iv) else {
            panic!("CBC needs its IV");
        };
        assert_eq!(
            source::<SecurityError>(&error),
            Some(&SecurityError::InvalidPbeParams)
        );
    }

    let unknown_cipher = Pbes2Params::new(
        params.key_derivation_func().clone(),
        AlgorithmIdentifier::with_parameters(
            "1.2.3.4".parse().unwrap(),
            Asn1OctetString::new(&[0; 16]),
        ),
    );
    let Err(error) = Pbes2::from_params(&unknown_cipher) else {
        panic!("1.2.3.4 is no cipher");
    };
    assert_eq!(
        source::<SecurityError>(&error),
        Some(&SecurityError::UnknownCipher)
    );
}
