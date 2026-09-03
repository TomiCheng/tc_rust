#![cfg(feature = "alloc")]

use tc_aes::AesEngine;
use tc_cipher::{
    AeadBlockCipher, AeadBlockError, AeadCipher, AeadCipherInit, AeadError, BlockCipher,
    CipherDirection,
};
use tc_crypto::AlgorithmName;
use tc_gcm_siv::{GcmSivBlockCipher, GcmSivInitError};
use tc_params::AeadBlockParams;

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

fn check_vector(key_hex: &str, nonce_hex: &str, aad_hex: &str, data_hex: &str, result_hex: &str) {
    let key = decode(key_hex);
    let nonce = decode(nonce_hex);
    let aad = decode(aad_hex);
    let plaintext = decode(data_hex);
    let expected = decode(result_hex);
    let params = AeadBlockParams::new(&key, &nonce, 16, &aad);

    let mut encryptor = GcmSivBlockCipher::new(AesEngine::new());
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(encryptor.get_update_output_size(plaintext.len()), 0);
    for chunk in plaintext.chunks(3) {
        assert_eq!(encryptor.process_bytes(chunk, &mut []).unwrap(), 0);
    }
    let mut encrypted = vec![0u8; encryptor.get_output_size(0)];
    let written = encryptor.do_final(&mut encrypted).unwrap();
    assert_eq!(written, expected.len());
    assert_eq!(encrypted, expected);
    assert_eq!(encryptor.mac(), Some(&expected[expected.len() - 16..]));

    let mut decryptor = GcmSivBlockCipher::new(AesEngine::new());
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    for chunk in encrypted.chunks(5) {
        assert_eq!(decryptor.process_bytes(chunk, &mut []).unwrap(), 0);
    }
    let mut recovered = vec![0u8; decryptor.get_output_size(0)];
    let recovered_len = decryptor.do_final(&mut recovered).unwrap();
    assert_eq!(recovered_len, plaintext.len());
    assert_eq!(recovered, plaintext);
}

#[test]
fn matches_rfc_8452_aes_128_vectors() {
    let key = "01000000000000000000000000000000";
    let nonce = "030000000000000000000000";
    check_vector(key, nonce, "", "", "dc20e2d83f25705bb49e439eca56de25");
    check_vector(
        key,
        nonce,
        "",
        "0100000000000000",
        "b5d839330ac7b786578782fff6013b815b287c22493a364c",
    );
    check_vector(
        key,
        nonce,
        "",
        "01000000000000000000000000000000",
        "743f7c8077ab25f8624e2e948579cf77303aaf90f6fe21199c6068577437a0c4",
    );
    check_vector(
        key,
        nonce,
        "01",
        "0200000000000000",
        "1e6daba35669f4273b0a1a2560969cdf790d99759abd1508",
    );
    check_vector(
        "36864200e0eaf5284d884a0e77d31646",
        "bae8e37fc83441b16034566b",
        "46bb91c3c5",
        "7a806c",
        "af60eb711bd85bc1e4d3e0a462e074eea428a8",
    );
}

#[test]
fn matches_rfc_8452_aes_256_vectors() {
    let key = "0100000000000000000000000000000000000000000000000000000000000000";
    let nonce = "030000000000000000000000";
    check_vector(key, nonce, "", "", "07f5f4169bbf55a8400cd47ea6fd400f");
    check_vector(
        key,
        nonce,
        "",
        "0100000000000000",
        "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28",
    );
    check_vector(
        key,
        nonce,
        "",
        "01000000000000000000000000000000",
        "85a01b63025ba19b7fd3ddfc033b3e76c9eac6fa700942702e90862383c6c366",
    );
}

#[test]
fn validates_parameters_order_and_authentication() {
    let key = [0x11u8; 16];
    let nonce = [0x22u8; 12];
    let params = AeadBlockParams::new(&key, &nonce, 16, b"initial");
    let mut cipher = GcmSivBlockCipher::new(AesEngine::new());

    assert!(matches!(
        cipher.init(
            CipherDirection::Encrypt,
            &AeadBlockParams::new(&[0u8; 24], &nonce, 16, &[]),
        ),
        Err(GcmSivInitError::InvalidKeyLength(24))
    ));
    assert!(matches!(
        cipher.init(
            CipherDirection::Encrypt,
            &AeadBlockParams::new(&key, &[0u8; 11], 16, &[]),
        ),
        Err(GcmSivInitError::InvalidNonceLength(11))
    ));
    assert!(matches!(
        cipher.init(
            CipherDirection::Encrypt,
            &AeadBlockParams::new(&key, &nonce, 12, &[]),
        ),
        Err(GcmSivInitError::InvalidMacSize(12))
    ));

    cipher.init(CipherDirection::Encrypt, &params).unwrap();
    cipher.process_bytes(b"message", &mut []).unwrap();
    assert_eq!(
        cipher.process_aad_bytes(b"late"),
        Err(AeadBlockError::Aead(AeadError::AadAfterData))
    );
    let mut encrypted = [0u8; 23];
    cipher.do_final(&mut encrypted).unwrap();

    encrypted[0] ^= 1;
    let mut decryptor = GcmSivBlockCipher::new(AesEngine::new());
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    decryptor.process_bytes(&encrypted, &mut []).unwrap();
    let mut output = [0xabu8; 7];
    assert_eq!(
        decryptor.do_final(&mut output),
        Err(AeadBlockError::Aead(AeadError::AuthenticationFailed))
    );
    assert_eq!(output, [0xab; 7]);
    assert_eq!(decryptor.mac(), None);
}

#[test]
fn exposes_metadata_and_reset_packet_semantics() {
    let key = [0x11u8; 16];
    let nonce = [0x22u8; 12];
    let params = AeadBlockParams::new(&key, &nonce, 16, b"header");
    let mut cipher = GcmSivBlockCipher::new(AesEngine::new());
    let mut name = String::new();
    cipher.write_algo_name(&mut name).unwrap();
    assert_eq!(name, "AES/GCM-SIV");
    assert_eq!(cipher.block_size(), 16);
    assert_eq!(cipher.underlying_cipher().block_size(), 16);

    cipher.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(cipher.get_update_output_size(99), 0);
    assert_eq!(cipher.get_output_size(7), 23);
    cipher.process_bytes(b"discard", &mut []).unwrap();
    cipher.reset();
    assert_eq!(cipher.get_output_size(0), 16);

    let mut first = [0u8; 16];
    cipher.do_final(&mut first).unwrap();
    assert_eq!(cipher.mac(), Some(first.as_slice()));
    let mut second = [0u8; 16];
    cipher.do_final(&mut second).unwrap();
    assert_eq!(first, second);
}
