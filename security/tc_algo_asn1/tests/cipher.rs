use tc_algo::params::key::KeyOwned;
use tc_algo_asn1::cipher::{Asn1Cipher, CipherDirection};
use tc_algo_asn1::{AlgoAsn1, AlgoAsn1Builder, AlgoAsn1Error, DefaultAlgoAsn1Builder};
use tc_asn1::{Asn1Object, Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};
use tc_asn1_cms::params::GcmParameters;
use tc_asn1_x509::alg::AlgorithmIdentifier;

fn asn1() -> Box<dyn AlgoAsn1> {
    DefaultAlgoAsn1Builder::default().build()
}

fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn run(cipher: &mut dyn Asn1Cipher, input: &[u8]) -> Result<Vec<u8>, AlgoAsn1Error> {
    let mut output = cipher.update(input)?;
    output.extend(cipher.finalize()?);
    Ok(output)
}

// Each row with its OID and the size of its key
const ROWS: [(&str, &str, usize); 21] = [
    ("AES-128-CBC", "2.16.840.1.101.3.4.1.2", 16),
    ("AES-192-CBC", "2.16.840.1.101.3.4.1.22", 24),
    ("AES-256-CBC", "2.16.840.1.101.3.4.1.42", 32),
    ("AES-128-GCM", "2.16.840.1.101.3.4.1.6", 16),
    ("AES-192-GCM", "2.16.840.1.101.3.4.1.26", 24),
    ("AES-256-GCM", "2.16.840.1.101.3.4.1.46", 32),
    ("AES-128-CCM", "2.16.840.1.101.3.4.1.7", 16),
    ("AES-192-CCM", "2.16.840.1.101.3.4.1.27", 24),
    ("AES-256-CCM", "2.16.840.1.101.3.4.1.47", 32),
    ("DES-CBC", "1.3.14.3.2.7", 8),
    ("DES-EDE3-CBC", "1.2.840.113549.3.7", 24),
    ("CAMELLIA-128-CBC", "1.2.392.200011.61.1.1.1.2", 16),
    ("CAMELLIA-192-CBC", "1.2.392.200011.61.1.1.1.3", 24),
    ("CAMELLIA-256-CBC", "1.2.392.200011.61.1.1.1.4", 32),
    ("SEED-CBC", "1.2.410.200004.1.4", 16),
    ("ARIA-128-CBC", "1.2.410.200046.1.1.2", 16),
    ("ARIA-192-CBC", "1.2.410.200046.1.1.7", 24),
    ("ARIA-256-CBC", "1.2.410.200046.1.1.12", 32),
    ("SM4-CBC", "1.2.156.10197.1.104.2", 16),
    ("CHACHA20-POLY1305", "1.2.840.113549.1.9.16.3.18", 32),
    ("aes-128-cbc", "2.16.840.1.101.3.4.1.2", 16),
];

#[test]
fn every_row_decrypts_by_its_algorithm_identifier_what_it_encrypted_by_name() {
    let asn1 = asn1();
    let message = b"a message longer than one block of any cipher";
    for (name, oid, key_size) in ROWS {
        let key = KeyOwned::new(vec![0x5a; key_size]);
        let mut cipher = asn1.cipher().get_by_name(name).unwrap();
        cipher.init(CipherDirection::Encrypt, &key).unwrap();
        let algorithm = cipher.algorithm().clone();
        assert_eq!(algorithm.algorithm().to_string(), oid, "{name}");
        let sealed = run(cipher.as_mut(), message).unwrap();
        assert_ne!(&sealed[..message.len()], message, "{name}");

        let mut cipher = asn1.cipher().get_by_id(&algorithm).unwrap();
        cipher.init(CipherDirection::Decrypt, &key).unwrap();
        assert_eq!(run(cipher.as_mut(), &sealed).unwrap(), message, "{name}");
    }
}

// SP 800-38A F.2.1: the first block, as the row pads the message after it
#[test]
fn aes_128_cbc_gives_the_first_block_of_sp_800_38a() {
    let algorithm = AlgorithmIdentifier::with_parameters(
        "2.16.840.1.101.3.4.1.2".parse().unwrap(),
        Asn1Object::OctetString(Asn1OctetString::new(&unhex(
            "000102030405060708090a0b0c0d0e0f",
        ))),
    );
    let key = KeyOwned::new(unhex("2b7e151628aed2a6abf7158809cf4f3c"));
    let mut cipher = asn1().cipher().get_by_id(&algorithm).unwrap();
    cipher.init(CipherDirection::Encrypt, &key).unwrap();
    let sealed = run(cipher.as_mut(), &unhex("6bc1bee22e409f96e93d7e117393172a")).unwrap();
    assert_eq!(sealed[..16], unhex("7649abac8119b246cee98e9b12e9197d"));
}

// The parameters made with the cipher are those of the first message; each message after has new
// ones, so no IV is used twice
#[test]
fn a_cipher_by_name_draws_a_new_iv_for_each_message() {
    let key = KeyOwned::new(vec![1; 16]);
    let mut cipher = asn1().cipher().get_by_name("AES-128-GCM").unwrap();
    let before = cipher.algorithm().clone();
    cipher.init(CipherDirection::Encrypt, &key).unwrap();
    assert_eq!(cipher.algorithm(), &before);
    run(cipher.as_mut(), b"first").unwrap();

    cipher.init(CipherDirection::Encrypt, &key).unwrap();
    assert_ne!(cipher.algorithm(), &before);
}

#[test]
fn a_cipher_by_name_has_no_parameters_to_decrypt_with() {
    let mut cipher = asn1().cipher().get_by_name("AES-128-CBC").unwrap();
    assert!(matches!(
        cipher.init(CipherDirection::Decrypt, &KeyOwned::new(vec![1; 16])),
        Err(AlgoAsn1Error::InvalidCipherParameters)
    ));
}

// The OID names the size of the key, so another size would make the AlgorithmIdentifier untrue
#[test]
fn a_key_of_another_size_than_the_oid_names_is_an_invalid_key() {
    let mut cipher = asn1().cipher().get_by_name("AES-128-CBC").unwrap();
    assert!(matches!(
        cipher.init(CipherDirection::Encrypt, &KeyOwned::new(vec![1; 32])),
        Err(AlgoAsn1Error::InvalidKey)
    ));
}

#[test]
fn an_iv_of_another_size_is_invalid_cipher_parameters() {
    let algorithm = AlgorithmIdentifier::with_parameters(
        "2.16.840.1.101.3.4.1.2".parse().unwrap(),
        Asn1Object::OctetString(Asn1OctetString::new(&[0; 8])),
    );
    let mut cipher = asn1().cipher().get_by_id(&algorithm).unwrap();
    assert!(matches!(
        cipher.init(CipherDirection::Decrypt, &KeyOwned::new(vec![1; 16])),
        Err(AlgoAsn1Error::InvalidCipherParameters)
    ));
}

// RFC 5084 GCMParameters: a nonce of 12 bytes and a tag of 16, which a changed byte fails
#[test]
fn aes_gcm_writes_a_nonce_of_12_bytes_and_a_tag_of_16_and_rejects_a_change() {
    let asn1 = asn1();
    let key = KeyOwned::new(vec![3; 32]);
    let mut cipher = asn1.cipher().get_by_name("AES-256-GCM").unwrap();
    cipher.init(CipherDirection::Encrypt, &key).unwrap();
    let algorithm = cipher.algorithm().clone();
    let mut sealed = run(cipher.as_mut(), b"message").unwrap();
    assert_eq!(sealed.len(), b"message".len() + 16);

    let der = algorithm
        .parameters()
        .unwrap()
        .encode_to_vec(&EncodingOptions::DER)
        .unwrap();
    let (_, gcm) = GcmParameters::decode(&der, &DecodingOptions::default()).unwrap();
    assert_eq!(gcm.nonce().as_bytes().len(), 12);
    assert_eq!(gcm.icv_len(), 16);

    sealed[0] ^= 1;
    let mut cipher = asn1.cipher().get_by_id(&algorithm).unwrap();
    cipher.init(CipherDirection::Decrypt, &key).unwrap();
    assert!(run(cipher.as_mut(), &sealed).is_err());
}

#[test]
fn a_name_or_an_oid_no_row_has_is_an_unknown_cipher() {
    let asn1 = asn1();
    assert!(matches!(
        asn1.cipher().get_by_name("AES/CBC/PKCS7PADDING"),
        Err(AlgoAsn1Error::UnknownCipher)
    ));
    let sha256 = AlgorithmIdentifier::new("2.16.840.1.101.3.4.2.1".parse().unwrap());
    assert!(matches!(
        asn1.cipher().get_by_id(&sha256),
        Err(AlgoAsn1Error::UnknownCipher)
    ));
}
