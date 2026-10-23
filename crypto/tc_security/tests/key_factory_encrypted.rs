//! 加密的 PKCS#8：解開 OpenSSL 加密的私鑰、兩種方案的加解密往返，以及錯誤的密碼與不能加密的方案。

#![cfg(all(
    feature = "key-factory",
    feature = "pbe",
    feature = "ec",
    feature = "aes",
    feature = "desede",
    feature = "md5",
    feature = "sha1",
    feature = "sha256"
))]

use std::error::Error;

use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use tc_asn1_pkcs::Pkcs5Algorithm;
use tc_security::key_factory::{self, KeyEncryption};
use tc_security::pbe::{self, Pbes2};
use tc_security::{AnyError, SecurityError};

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

/// 同一把私鑰以 `openssl pkcs8 -topk8 -passout pass:password` 加密：`-v2 aes-256-cbc -v2prf
/// hmacWithSHA256 -iter 2048`。
const AES256_SHA256: &str = concat!(
    "3081f4305f06092a864886f70d01050d3052303106092a864886f70d01050c302404109720f2fe1c4e34713399cdc892",
    "ef838602020800300c06082a864886f70d02090500301d060960864801650304012a04101cbaa2e315e193a0fd4d80df",
    "af1a5829048190a905cdf2717d2f58698f5e5d08a7ff19ef70cb88e9b0539f1ef1027d2374409afc2f4920c4e328b6e6",
    "e6a2758b36714d4a2cc1ce0f599ead3ccd73de1b4e0074871077784a6d1d19616d64ad644a44846718cdc14de42a42c0",
    "8e6c5ac6b19c3dcd07d6bcc7fe717c804e48f90371a0781a2c8c9e981c5e057b794f4d91d9975eaa98a7a83b3a7caf7a",
    "686859fb0983ba",
);

/// `-v2 aes-128-cbc -v2prf hmacWithSHA1 -iter 1000`。
const AES128_SHA1: &str = concat!(
    "3081e6305106092a864886f70d01050d3044302306092a864886f70d01050c30160410be231e4a99c2760d2e46e0a5c9",
    "06e2a6020203e8301d06096086480165030401020410d7f108efaf92f65f2f85a5cdaba51b76048190ccabcd41ba2abf",
    "28f74e4f05e062fd8a449c5306e3c88977373e00db9a7e726b73d23e6c4831214a8c81e5f10b8b0d6bead0cd159e5adf",
    "2a8295f0cb3edb331586fe0808d312bef5624d5f6bdb97dc11f59b542be9fd460387b00e78c782150e071fbea1ea58af",
    "e66f50c207285cded5e580256a0ce037134b3c7752cf64297fffdbe2b72f5b0115209f8ef275d74f80",
);

/// `-v1 PBE-SHA1-3DES -iter 2048`，PKCS#12 的方案。
const SHA1_3DES: &str = concat!(
    "3081b1301c060a2a864886f70d010c0103300e0408349a85fd6c21ed1102020800048190caacb4b4def07b295cffc86a",
    "0ab8f0f8a7a3c86721fb8d33a9098613fb3c0a64332d7a37e2da979abd9454d83608f95f71d332057c8322958cdc0498",
    "60d2c3bcc515ba56cb2fc4328c9c700da7ff4038e905463e77b51631621e5aa495ca1739a316e768514ab6fd7f3fb955",
    "af0aa7e0a31800cf2a6ce19864e1acc84907e5e0cb6de73f903bce086637f94a1287fd43",
);

fn plain_key_der() -> Vec<u8> {
    let key = key_factory::private_key_from_der(&hex(PLAIN)).unwrap();
    key_factory::private_key_to_der(&key).unwrap().to_vec()
}

#[test]
fn openssl_encrypted_keys_decrypt_with_the_password() {
    for encrypted in [AES256_SHA256, AES128_SHA1, SHA1_3DES] {
        let key = key_factory::private_key_from_encrypted_der("password", &hex(encrypted)).unwrap();
        assert_eq!(
            key_factory::private_key_to_der(&key).unwrap()[..],
            plain_key_der()[..]
        );
        assert!(key_factory::private_key_from_encrypted_der("passw0rd", &hex(encrypted)).is_err());
    }
}

#[test]
fn keys_encrypted_with_either_scheme_decrypt_back() {
    let key = key_factory::private_key_from_der(&hex(PLAIN)).unwrap();
    let pbes2 = Pbes2::generate(
        &"2.16.840.1.101.3.4.1.42".parse().unwrap(),
        &Pkcs5Algorithm::HMAC_WITH_SHA256.oid(),
        &[3; 16],
        2048,
        &mut UnwrapErr(SysRng),
    )
    .unwrap();
    for encryption in [
        KeyEncryption::Scheme {
            entry: pbe::get_by_name("PBEWithSHAAnd3-KeyTripleDES-CBC").unwrap(),
            salt: &[1, 2, 3, 4, 5, 6, 7, 8],
            iteration_count: 2048,
        },
        KeyEncryption::Pbes2(&pbes2),
    ] {
        let der = key_factory::private_key_to_encrypted_der(&key, "pässword", &encryption).unwrap();
        let back = key_factory::private_key_from_encrypted_der("pässword", &der).unwrap();
        assert_eq!(
            key_factory::private_key_to_der(&back).unwrap()[..],
            plain_key_der()[..]
        );
    }
}

/// MAC 的方案（`PBEWITHHMAC…`）與沒有 OID 的方案（OpenSSL 的 `EVP_BytesToKey`）寫不成
/// `EncryptedPrivateKeyInfo`。
#[test]
fn schemes_that_cannot_encrypt_a_key_are_refused() {
    let key = key_factory::private_key_from_der(&hex(PLAIN)).unwrap();
    for name in ["PBEWITHHMACSHA1", "PBEWITHMD5AND256BITAES-CBC-OPENSSL"] {
        let encryption = KeyEncryption::Scheme {
            entry: pbe::get_by_name(name).unwrap(),
            salt: &[1; 8],
            iteration_count: 1,
        };
        let Err(error) = key_factory::private_key_to_encrypted_der(&key, "password", &encryption)
        else {
            panic!("{name} cannot encrypt a key");
        };
        assert_eq!(
            source::<SecurityError>(&error),
            Some(&SecurityError::UnknownPbe),
            "{name}"
        );
    }
}

/// `-v1 PBE-SHA1-RC4-128 -iter 2048 -provider legacy`，PKCS#12 的 128 bits RC4 方案。
#[cfg(feature = "rc4")]
const SHA1_RC4_128: &str = concat!(
    "3081ab301c060a2a864886f70d010c0101300e04084f3de0e4522741ff0202080004818aa740dd40e6fb70dcc6e476ea",
    "925ab5230bf472d613dd2c7961f2a23856a6a387fba93d72d4e20cc83b90882189c44d28dd7f7d0725133a5553b1f846",
    "4f092596d84288362ff3fb08bf6522c8295410a0802996ca0a6f9c81b66dfe658e0b04f570c93c4db9bfce429f09fe3d",
    "a948d35dc4b677683f46d18a9d1d645d152396ce27c7d78b761cc396e9f8",
);

/// `-v1 PBE-SHA1-RC4-40 -iter 2048 -provider legacy`，PKCS#12 的 40 bits RC4 方案。
#[cfg(feature = "rc4")]
const SHA1_RC4_40: &str = concat!(
    "3081ab301c060a2a864886f70d010c0102300e0408378d2e2566c2d10a0202080004818a03920ff3da172fefdc485246",
    "f59310483bd8656f0e885413811c6f0020f4dd9741fbf0f7c29d2ac03ac562b52117cd60159f89902bd1cd52d5f3c8b1",
    "227919047cfd08513d70601e5369c0136ffaa5cdf431c2808d5741e3daeebdabf2b1086f8125be2297861d354dcc85d9",
    "0cb6312d09074e6bed72db71ce75c64a79ff3ba8e8ec9af4d334f737554b",
);

/// RC4 沒有 IV，方案只產生金鑰，同 BC。
#[cfg(feature = "rc4")]
#[test]
fn openssl_rc4_encrypted_keys_decrypt_and_rc4_schemes_encrypt_back() {
    for encrypted in [SHA1_RC4_128, SHA1_RC4_40] {
        let key = key_factory::private_key_from_encrypted_der("password", &hex(encrypted)).unwrap();
        assert_eq!(
            key_factory::private_key_to_der(&key).unwrap()[..],
            plain_key_der()[..]
        );
    }

    let key = key_factory::private_key_from_der(&hex(PLAIN)).unwrap();
    for name in ["PBEWITHSHAAND128BITRC4", "PBEWITHSHAAND40BITRC4"] {
        let encryption = KeyEncryption::Scheme {
            entry: pbe::get_by_name(name).unwrap(),
            salt: &[9; 8],
            iteration_count: 2048,
        };
        let der = key_factory::private_key_to_encrypted_der(&key, "password", &encryption).unwrap();
        let back = key_factory::private_key_from_encrypted_der("password", &der).unwrap();
        assert_eq!(
            key_factory::private_key_to_der(&back).unwrap()[..],
            plain_key_der()[..]
        );
    }
}
