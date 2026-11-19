use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
use tc_asn1_pkcs::{EncryptedPrivateKeyInfo, PrivateKeyInfo};
use tc_pkcs::operator::encrypted_private_key_info::{PbeParams, Pbes2Params};
use tc_pkcs::{DefaultPkcsOperatorBuilder, PkcsError, PkcsOperatorBuilder};

const PASSWORD: &str = "correct horse";
const KEY: &[u8] = include_bytes!("data/x25519.der");

fn decode<T: Decode>(der: &[u8]) -> T {
    T::decode(der, &DecodingOptions::default()).unwrap().1
}

fn der<T: Encode>(value: &T) -> Vec<u8> {
    value.encode_to_vec(&EncodingOptions::DER).unwrap()
}

#[test]
fn the_keys_openssl_encrypted_with_each_scheme_decrypt_to_the_same_private_key_info() {
    let oper = DefaultPkcsOperatorBuilder::default().build();
    let files: [(&str, &[u8]); 7] = [
        (
            "PBES2 AES-256-CBC SHA-256",
            include_bytes!("data/pbes2_aes256_sha256.der"),
        ),
        (
            "PBES2 AES-128-CBC SHA-512",
            include_bytes!("data/pbes2_aes128_sha512.der"),
        ),
        (
            "PBES2 DES-EDE3-CBC SHA-1",
            include_bytes!("data/pbes2_des3_sha1.der"),
        ),
        (
            "PBES2 RC2-CBC SHA-1",
            include_bytes!("data/pbes2_rc2_sha1.der"),
        ),
        (
            "PKCS#12 SHA-1 3DES",
            include_bytes!("data/pkcs12_sha1_3des.der"),
        ),
        (
            "PKCS#12 SHA-1 RC2-40",
            include_bytes!("data/pkcs12_sha1_rc2_40.der"),
        ),
        ("PKCS#5 MD5 DES", include_bytes!("data/pkcs5_md5_des.der")),
    ];
    for (scheme, file) in files {
        let info = oper
            .encrypted_private_key_info()
            .decrypt(PASSWORD, &decode(file))
            .unwrap_or_else(|error| panic!("{scheme}: {error}"));
        assert_eq!(der(&info), KEY, "{scheme}");
    }
}

#[test]
fn a_key_encrypted_with_pbes2_decrypts_with_the_same_password_only() {
    let oper = DefaultPkcsOperatorBuilder::default().build();
    let key: PrivateKeyInfo = decode(KEY);
    let params = Pbes2Params::new(
        PASSWORD,
        vec![7; 16],
        2048,
        "1.2.840.113549.2.9".parse().unwrap(),
        "2.16.840.1.101.3.4.1.42".parse().unwrap(),
        vec![9; 16],
    );
    let sealed = oper
        .encrypted_private_key_info()
        .encrypt_by_name("PBES2", &params, &key)
        .unwrap();
    assert_eq!(
        sealed.encryption_algorithm().algorithm().to_string(),
        "1.2.840.113549.1.5.13"
    );
    let opened = oper
        .encrypted_private_key_info()
        .decrypt(PASSWORD, &sealed)
        .unwrap();
    assert_eq!(opened, key);
    assert!(
        oper.encrypted_private_key_info()
            .decrypt("wrong horse", &sealed)
            .is_err()
    );
}

#[test]
fn a_key_encrypted_with_rc2_cbc_under_pbes2_reads_back() {
    let oper = DefaultPkcsOperatorBuilder::default().build();
    let key: PrivateKeyInfo = decode(KEY);
    let params = Pbes2Params::new(
        PASSWORD,
        vec![7; 16],
        1000,
        "1.2.840.113549.2.7".parse().unwrap(),
        "1.2.840.113549.3.2".parse().unwrap(),
        vec![9; 8],
    );
    let sealed = oper
        .encrypted_private_key_info()
        .encrypt_by_oid(&"1.2.840.113549.1.5.13".parse().unwrap(), &params, &key)
        .unwrap();
    let opened = oper
        .encrypted_private_key_info()
        .decrypt(PASSWORD, &sealed)
        .unwrap();
    assert_eq!(opened, key);
}

#[test]
fn a_pbe_scheme_of_tc_algo_is_written_by_its_oid_and_reads_back() {
    let oper = DefaultPkcsOperatorBuilder::default().build();
    let key: PrivateKeyInfo = decode(KEY);
    let params = PbeParams::new(PASSWORD, vec![3; 8], 1000);
    let sealed = oper
        .encrypted_private_key_info()
        .encrypt_by_name("PBEwithSHA-1and3-keyDESEDE-CBC", &params, &key)
        .unwrap();
    assert_eq!(
        sealed.encryption_algorithm().algorithm().to_string(),
        "1.2.840.113549.1.12.1.3"
    );
    let encoded = der(&sealed);
    let opened = oper
        .encrypted_private_key_info()
        .decrypt(PASSWORD, &decode::<EncryptedPrivateKeyInfo>(&encoded))
        .unwrap();
    assert_eq!(opened, key);
}

#[test]
fn an_unknown_scheme_or_params_of_another_type_are_refused() {
    let oper = DefaultPkcsOperatorBuilder::default().build();
    let key: PrivateKeyInfo = decode(KEY);
    let params = PbeParams::new(PASSWORD, vec![3; 8], 1000);
    let provider = oper.encrypted_private_key_info();

    let error = provider
        .encrypt_by_name("NO-SUCH-SCHEME", &params, &key)
        .unwrap_err();
    assert!(matches!(error, PkcsError::UnknownEncryption));
    let error = provider
        .encrypt_by_name("PBES2", &params, &key)
        .unwrap_err();
    assert!(matches!(error, PkcsError::InvalidEncryptionParams));
    // The OpenSSL scheme of tc_algo has no OID to write
    let error = provider
        .encrypt_by_name("PBEwithMD5and256bitAES-CBC-OpenSSL", &params, &key)
        .unwrap_err();
    assert!(matches!(error, PkcsError::UnknownEncryption));
}
