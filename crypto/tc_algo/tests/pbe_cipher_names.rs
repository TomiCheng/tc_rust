#![cfg(all(
    feature = "aes",
    feature = "des",
    feature = "rc-cipher",
    feature = "rc4-family"
))]

use tc_algo::params::{cipher::KeyWithIvOwned, key::KeyOwned};
use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};

// The PBE names of Bouncy Castle's CipherUtilities, with the cipher each names
const NAMES: &[(&str, &str)] = &[
    ("PBEWITHSHAAND128BITRC4", "ARC4"),
    ("PBEWITHSHA1AND128BITRC4", "ARC4"),
    ("PBEWITHSHAAND40BITRC4", "ARC4"),
    ("PBEWITHSHA1AND40BITRC4", "ARC4"),
    ("PBEWITHSHA1ANDDES-CBC", "DES/CBC/PKCS7PADDING"),
    ("PBEWITHSHA1ANDDES", "DES/CBC/PKCS7PADDING"),
    ("PBEWITHSHA1ANDRC2-CBC", "RC2/CBC/PKCS7PADDING"),
    ("PBEWITHSHA1ANDRC2", "RC2/CBC/PKCS7PADDING"),
    ("PBEWITHSHAAND128BITRC2-CBC", "RC2/CBC/PKCS7PADDING"),
    ("PBEWITHSHA1AND128BITRC2-CBC", "RC2/CBC/PKCS7PADDING"),
    ("PBEWITHSHAAND40BITRC2-CBC", "RC2/CBC/PKCS7PADDING"),
    ("PBEWITHSHA1AND40BITRC2-CBC", "RC2/CBC/PKCS7PADDING"),
    ("PBEWITHSHAAND3-KEYTRIPLEDES-CBC", "DESEDE/CBC/PKCS7PADDING"),
    (
        "PBEWITHSHA1AND3-KEYTRIPLEDES-CBC",
        "DESEDE/CBC/PKCS7PADDING",
    ),
    ("PBEWITHSHAAND3KEYTRIPLEDES", "DESEDE/CBC/PKCS7PADDING"),
    ("PBEWITHSHA1ANDDESEDE", "DESEDE/CBC/PKCS7PADDING"),
    ("PBEWITHSHAAND2-KEYTRIPLEDES-CBC", "DESEDE/CBC/PKCS7PADDING"),
    (
        "PBEWITHSHA1AND2-KEYTRIPLEDES-CBC",
        "DESEDE/CBC/PKCS7PADDING",
    ),
    ("PBEWITHSHAAND128BITAES-CBC-BC", "AES/CBC/PKCS7PADDING"),
    ("PBEWITHSHA1AND128BITAES-CBC-BC", "AES/CBC/PKCS7PADDING"),
    ("PBEWITHSHA-1AND128BITAES-CBC-BC", "AES/CBC/PKCS7PADDING"),
    ("PBEWITHSHAAND192BITAES-CBC-BC", "AES/CBC/PKCS7PADDING"),
    ("PBEWITHSHA1AND192BITAES-CBC-BC", "AES/CBC/PKCS7PADDING"),
    ("PBEWITHSHA-1AND192BITAES-CBC-BC", "AES/CBC/PKCS7PADDING"),
    ("PBEWITHSHAAND256BITAES-CBC-BC", "AES/CBC/PKCS7PADDING"),
    ("PBEWITHSHA1AND256BITAES-CBC-BC", "AES/CBC/PKCS7PADDING"),
    ("PBEWITHSHA-1AND256BITAES-CBC-BC", "AES/CBC/PKCS7PADDING"),
    ("PBEWITHSHA256AND128BITAES-CBC-BC", "AES/CBC/PKCS7PADDING"),
    ("PBEWITHSHA-256AND128BITAES-CBC-BC", "AES/CBC/PKCS7PADDING"),
    ("PBEWITHSHA256AND192BITAES-CBC-BC", "AES/CBC/PKCS7PADDING"),
    ("PBEWITHSHA-256AND192BITAES-CBC-BC", "AES/CBC/PKCS7PADDING"),
    ("PBEWITHSHA256AND256BITAES-CBC-BC", "AES/CBC/PKCS7PADDING"),
    ("PBEWITHSHA-256AND256BITAES-CBC-BC", "AES/CBC/PKCS7PADDING"),
    ("PBEWITHMD5AND128BITAES-CBC-OPENSSL", "AES/CBC/PKCS7PADDING"),
    ("PBEWITHMD5AND192BITAES-CBC-OPENSSL", "AES/CBC/PKCS7PADDING"),
    ("PBEWITHMD5AND256BITAES-CBC-OPENSSL", "AES/CBC/PKCS7PADDING"),
];

// The PBE OIDs of PKCS#5 and PKCS#12 that Bouncy Castle's CipherUtilities maps to a cipher
const OIDS: &[(&str, &str)] = &[
    ("1.2.840.113549.1.12.1.1", "ARC4"),
    ("1.2.840.113549.1.12.1.2", "ARC4"),
    ("1.2.840.113549.1.5.10", "DES/CBC/PKCS7PADDING"),
    ("1.2.840.113549.1.5.11", "RC2/CBC/PKCS7PADDING"),
    ("1.2.840.113549.1.12.1.5", "RC2/CBC/PKCS7PADDING"),
    ("1.2.840.113549.1.12.1.6", "RC2/CBC/PKCS7PADDING"),
    ("1.2.840.113549.1.12.1.3", "DESEDE/CBC/PKCS7PADDING"),
    ("1.2.840.113549.1.12.1.4", "DESEDE/CBC/PKCS7PADDING"),
];

#[test]
fn every_pbe_name_and_oid_of_bouncy_castle_is_a_name_of_the_cipher_it_encrypts_with() {
    let algo = DefaultAlgoBuilder::default().build();
    let ciphers = algo.cipher();
    for &(name, cipher) in NAMES {
        let entry = ciphers
            .algorithms()
            .find(|entry| entry.aliases().iter().any(|alias| alias == name))
            .unwrap_or_else(|| panic!("{name}"));
        assert_eq!(entry.name(), cipher, "{name}");
    }
    for &(dotted, cipher) in OIDS {
        let oid = dotted.parse().unwrap();
        let entry = ciphers
            .algorithms()
            .find(|entry| entry.oids().contains(&oid))
            .unwrap_or_else(|| panic!("{dotted}"));
        assert_eq!(entry.name(), cipher, "{dotted}");
    }
}

// A key and an IV derived from a password, as PKCS#12 gives them, go to the cipher as they would
// under its own name; a 5-byte key is 40-bit RC2
#[test]
fn a_pbe_name_encrypts_as_the_cipher_it_names() {
    let algo = DefaultAlgoBuilder::default().build();
    let ciphers = algo.cipher();
    let message = b"a message of no particular length";

    let params = KeyWithIvOwned::new(vec![0x42; 24], vec![0x24; 8]);
    let expected = ciphers
        .encrypt_by_name("DESEDE/CBC/PKCS7PADDING", &params, message)
        .unwrap();
    let sealed = ciphers
        .encrypt_by_name("PBEWithSHAAnd3-KeyTripleDES-CBC", &params, message)
        .unwrap();
    assert_eq!(sealed, expected);

    let params = KeyWithIvOwned::new(vec![0x42; 5], vec![0x24; 8]);
    let expected = ciphers
        .encrypt_by_name("RC2/CBC/PKCS7PADDING", &params, message)
        .unwrap();
    let sealed = ciphers
        .encrypt_by_name("PBEWITHSHAAND40BITRC2-CBC", &params, message)
        .unwrap();
    assert_eq!(sealed, expected);

    let params = KeyOwned::new(vec![0x42; 16]);
    let expected = ciphers.encrypt_by_name("ARC4", &params, message).unwrap();
    let sealed = ciphers
        .encrypt_by_name("PBEWITHSHAAND128BITRC4", &params, message)
        .unwrap();
    assert_eq!(sealed, expected);
}
