#![cfg(feature = "alloc")]

use tc_aes::AesEngine;
use tc_cipher::{AeadBlockError, AeadBlockInitError, AeadError, BlockCipher};
use tc_crypto::AlgorithmName;
use tc_gmac::{CreateError, GMac};
use tc_macs::{Mac, MacInit};
use tc_params::KeyWithIvRef;

fn decode(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect()
}

fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("invalid hexadecimal digit"),
    }
}

fn check_vector(key_hex: &str, nonce_hex: &str, aad_hex: &str, tag_hex: &str) {
    let key = decode(key_hex);
    let nonce = decode(nonce_hex);
    let aad = decode(aad_hex);
    let expected = decode(tag_hex);
    let params = KeyWithIvRef::new(&key, &nonce);
    let mut mac = GMac::with_mac_size(AesEngine::new(), expected.len()).unwrap();
    mac.init(&params).unwrap();
    for chunk in aad.chunks(3) {
        mac.update(chunk).unwrap();
    }
    let mut output = vec![0u8; mac.mac_size()];
    assert_eq!(mac.do_final(&mut output).unwrap(), expected.len());
    assert_eq!(output, expected);
}

#[test]
fn matches_nist_cavp_vectors() {
    check_vector(
        "11754cd72aec309bf52f7687212e8957",
        "3c819d9a9bed087615030b65",
        "",
        "250327c674aaf477aef2675748cf6971",
    );
    check_vector(
        "272f16edb81a7abbea887357a58c1917",
        "794ec588176c703d3d2a7a07",
        "",
        "b6e6f197168f5049aeda32dafbdaeb",
    );
    check_vector(
        "b01e45cc3088aaba9fa43d81d481823f",
        "5a2c4a66468713456a4bd5e1",
        "",
        "014280f944f53c681164b2ff",
    );
    check_vector(
        "77be63708971c4e240d1cb79e8d77feb",
        "e0e00f19fed7ba0136a797f3",
        "7a43ec1d9c0a5a78a0b16533a6213cab",
        "209fcc8d3675ed938e9c7166709dd946",
    );
    check_vector(
        "bea48ae4980d27f357611014d4486625",
        "32bddb5c3aa998a08556454c",
        "8a50b0b8c7654bced884f7f3afda2ead",
        "8e0f6d8bf05ffebe6f500eb1",
    );
    check_vector(
        "99e3e8793e686e571d8285c564f75e2b",
        "c2dd0ab868da6aa8ad9c0d23",
        concat!(
            "b668e42d4e444ca8b23cfdd95a9fedd5",
            "178aa521144890b093733cf5cf22526c",
            "5917ee476541809ac6867a8c399309fc"
        ),
        "3f4fba100eaf1f34b0baadaae9995d85",
    );
    check_vector(
        "d0f1f4defa1e8c08b4b26d576392027c",
        concat!(
            "42b4f01eb9f5a1ea5b1eb73b0fb0baed",
            "54f387ecaa0393c7d7dffc6af50146ec",
            "c021abf7eb9038d4303d91f8d741a117",
            "43166c0860208bcc02c6258fd9511a2f",
            "a626f96d60b72fcff773af4e88e7a923",
            "506e4916ecbd814651e9f445adef4ad6",
            "a6b6c7290cc13b956130eef5b837c939",
            "fcac0cbbcc9656cd75b13823ee5acdac"
        ),
        "",
        "7ab49b57ddf5f62c427950111c5c4f0d",
    );
}

#[test]
fn reset_discards_aad_but_finalization_requires_a_fresh_nonce() {
    let key = decode("77be63708971c4e240d1cb79e8d77feb");
    let nonce = decode("e0e00f19fed7ba0136a797f3");
    let aad = decode("7a43ec1d9c0a5a78a0b16533a6213cab");
    let expected = decode("209fcc8d3675ed938e9c7166709dd946");
    let params = KeyWithIvRef::new(&key, &nonce);
    let mut mac = GMac::new(AesEngine::new()).unwrap();
    mac.init(&params).unwrap();
    mac.update(b"discard this").unwrap();
    mac.reset();
    mac.update(&aad).unwrap();
    let mut output = [0u8; 16];
    mac.do_final(&mut output).unwrap();
    assert_eq!(output.as_slice(), expected);

    mac.reset();
    assert_eq!(
        mac.update(&aad),
        Err(AeadBlockError::Aead(AeadError::AlreadyFinalised))
    );
    assert_eq!(mac.init(&params), Err(AeadBlockInitError::NonceReuse));

    let fresh_nonce = [0x33u8; 12];
    mac.init(&KeyWithIvRef::new(&key, &fresh_nonce)).unwrap();
    assert_eq!(mac.update(&aad), Ok(()));
}

#[test]
fn validates_construction_and_exposes_metadata() {
    assert!(matches!(
        GMac::with_mac_size(AesEngine::new(), 3),
        Err(CreateError::InvalidMacSize(3))
    ));
    assert!(matches!(
        GMac::with_mac_size(AesEngine::new(), 17),
        Err(CreateError::InvalidMacSize(17))
    ));

    let mac = GMac::new(AesEngine::new()).unwrap();
    let mut name = String::new();
    mac.write_algo_name(&mut name).unwrap();
    assert_eq!(name, "AES-GMAC");
    assert_eq!(mac.mac_size(), 16);
    assert_eq!(mac.underlying_cipher().block_size(), 16);
}
