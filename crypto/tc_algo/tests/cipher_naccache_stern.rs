#![cfg(feature = "naccache-stern")]

use tc_algo::ErrorKind;
use tc_algo::cipher::{self, CipherDirection};
use tc_algo::params::{AnyKeyParams, AnyParams, AnyPrivateKey, AnyPublicKey, SecretKey};
use tc_bigint::PaddedBigUint;
use tc_naccache_stern::{NaccacheSternPrivateKey, NaccacheSternPublicKey};

// The toy example of the paper: phi(n) has the small primes 3 to 17, whose product sigma bounds
// the message, and g = 131
const P: u64 = 2 * 101 * 3 * 5 * 7 + 1;
const Q: u64 = 2 * 191 * 11 * 13 * 17 + 1;
const N: u64 = P * Q;
const G: u64 = 131;
const SIGMA: u64 = 3 * 5 * 7 * 11 * 13 * 17;

const NAME: &str = "NACCACHESTERN/NONE/NOPADDING";

fn public() -> AnyParams {
    let key = NaccacheSternPublicKey::new(PaddedBigUint::from(G), PaddedBigUint::from(N), 18);
    AnyParams::new(AnyKeyParams::Public(AnyPublicKey::NaccacheStern(key)))
}

fn private() -> AnyParams {
    let key = NaccacheSternPrivateKey::new(
        PaddedBigUint::from(G),
        PaddedBigUint::from(N),
        18,
        vec![3, 5, 7, 11, 13, 17],
        PaddedBigUint::from((P - 1) * (Q - 1)),
    );
    AnyParams::new(AnyKeyParams::Private(AnyPrivateKey::NaccacheStern(key)))
}

fn number(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .fold(0, |value, &byte| value << 8 | u64::from(byte))
}

fn power_mod(base: u64, exponent: u64, modulus: u64) -> u64 {
    let (mut result, mut base, mut exponent) = (1u128, u128::from(base), exponent);
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = result * base % u128::from(modulus);
        }
        base = base * base % u128::from(modulus);
        exponent >>= 1;
    }
    result as u64
}

#[test]
fn the_paper_example_encrypts_to_g_to_the_m_and_decrypts_back() {
    let ciphertext = cipher::encrypt(NAME, &public(), &[0, 202]).unwrap();
    assert_eq!(number(&ciphertext), power_mod(G, 202, N));
    let plaintext = cipher::decrypt(NAME, &private(), &ciphertext).unwrap();
    assert_eq!(number(&plaintext), 202);
}

#[test]
fn multiplying_two_ciphertexts_adds_their_messages_modulo_sigma() {
    let first = cipher::encrypt(NAME, &public(), &[0x80, 0x00]).unwrap();
    let second = cipher::encrypt(NAME, &public(), &[0x90, 0x00]).unwrap();
    let product = (u128::from(number(&first)) * u128::from(number(&second)) % u128::from(N)) as u64;
    let product = product.to_be_bytes()[8 - first.len()..].to_vec();
    let sum = cipher::decrypt(NAME, &private(), &product).unwrap();
    assert_eq!(number(&sum), (0x8000 + 0x9000) % SIGMA);
}

#[test]
fn the_same_message_always_gives_the_same_ciphertext_whichever_key_encrypts() {
    let once = cipher::encrypt(NAME, &public(), &[0, 202]).unwrap();
    assert_eq!(cipher::encrypt(NAME, &public(), &[0, 202]).unwrap(), once);
    // The private key encrypts too, as in Bouncy Castle
    assert_eq!(cipher::encrypt(NAME, &private(), &[0, 202]).unwrap(), once);
}

#[test]
fn the_public_key_does_not_decrypt() {
    let mut cipher = cipher::get_by_name(NAME).unwrap();
    let error = cipher
        .init(CipherDirection::Decrypt, &public())
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);
}

#[test]
fn a_message_longer_than_the_input_block_is_a_data_length_error() {
    // Sigma has 18 bits, so the input block is two bytes
    let error = cipher::encrypt(NAME, &public(), &[1, 2, 3]).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::DataLength);
}

#[test]
fn names_take_no_padding_but_none() {
    for name in [
        "NaccacheStern",
        "naccache-stern",
        "NACCACHE_STERN//NOPADDING",
    ] {
        let cipher = cipher::get_by_name(name).unwrap();
        assert_eq!(cipher.entry().name(), NAME, "{name}");
    }
    for name in [
        "NACCACHESTERN/NONE/PKCS1PADDING",
        "NACCACHESTERN/NONE/OAEPPADDING",
    ] {
        let error = cipher::get_by_name(name).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnknownCipher, "{name}");
    }
}

#[test]
fn the_table_has_naccache_stern_once_and_without_an_oid() {
    let entries: Vec<_> = cipher::algorithms()
        .filter(|entry| entry.name().starts_with("NACCACHESTERN/"))
        .collect();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].oids().is_empty());
}

#[test]
fn naccache_stern_refuses_a_secret_key_and_an_operation_field() {
    let secret = AnyParams::new(AnyKeyParams::Secret(SecretKey::new(vec![1; 16])));
    let mut with_iv = public();
    with_iv.op.iv = Some(vec![0; 16]);
    for params in [secret, with_iv] {
        let mut cipher = cipher::get_by_name(NAME).unwrap();
        let error = cipher.init(CipherDirection::Encrypt, &params).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}
