#![cfg(feature = "alloc")]

use tc_aes::AesEngine;
use tc_cipher::{
    AeadBlockCipher, AeadBlockError, AeadBlockInitError, AeadCipher, AeadCipherInit, AeadError,
    BlockCipher, CipherDirection,
};
use tc_crypto::AlgorithmName;
use tc_gcm::GcmBlockCipher;
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

fn check_vector(
    key_hex: &str,
    plaintext_hex: &str,
    aad_hex: &str,
    nonce_hex: &str,
    ciphertext_hex: &str,
    tag_hex: &str,
) {
    let key = decode(key_hex);
    let plaintext = decode(plaintext_hex);
    let aad = decode(aad_hex);
    let nonce = decode(nonce_hex);
    let expected_ciphertext = decode(ciphertext_hex);
    let expected_tag = decode(tag_hex);
    let params = AeadBlockParams::new(&key, &nonce, expected_tag.len(), &aad);

    let mut encryptor = GcmBlockCipher::new(AesEngine::new());
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    let mut encrypted = vec![0u8; encryptor.get_output_size(plaintext.len())];
    let mut written = encryptor.process_bytes(&plaintext, &mut encrypted).unwrap();
    written += encryptor.do_final(&mut encrypted[written..]).unwrap();
    let expected: Vec<u8> = expected_ciphertext
        .iter()
        .chain(&expected_tag)
        .copied()
        .collect();
    assert_eq!(written, expected.len());
    assert_eq!(encrypted, expected);
    assert_eq!(encryptor.mac(), Some(expected_tag.as_slice()));

    let mut decryptor = GcmBlockCipher::new(AesEngine::new());
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    let mut recovered = vec![0u8; decryptor.get_output_size(encrypted.len())];
    let mut recovered_len = 0;
    for chunk in encrypted.chunks(7) {
        recovered_len += decryptor
            .process_bytes(chunk, &mut recovered[recovered_len..])
            .unwrap();
    }
    recovered_len += decryptor.do_final(&mut recovered[recovered_len..]).unwrap();
    assert_eq!(recovered_len, plaintext.len());
    assert_eq!(recovered, plaintext);
    assert_eq!(decryptor.mac(), Some(expected_tag.as_slice()));
}

#[test]
fn matches_nist_and_bc_vectors() {
    check_vector(
        "00000000000000000000000000000000",
        "",
        "",
        "000000000000000000000000",
        "",
        "58e2fccefa7e3061367f1d57a4e7455a",
    );
    check_vector(
        "00000000000000000000000000000000",
        "",
        "",
        "000000000000000000000000",
        "",
        "58e2fcce",
    );
    check_vector(
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "",
        "000000000000000000000000",
        "0388dace60b6a392f328c2b971b2fe78",
        "ab6e47d42cec13bdf53a67b21257bddf",
    );
    check_vector(
        "feffe9928665731c6d6a8f9467308308",
        concat!(
            "d9313225f88406e5a55909c5aff5269a",
            "86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525",
            "b16aedf5aa0de657ba637b391aafd255"
        ),
        "",
        "cafebabefacedbaddecaf888",
        concat!(
            "42831ec2217774244b7221b784d0d49c",
            "e3aa212f2c02a4e035c17e2329aca12e",
            "21d514b25466931c7d8f6a5aac84aa05",
            "1ba30b396a0aac973d58e091473f5985"
        ),
        "4d5c2af327cd64a62cf35abd2ba6fab4",
    );
    check_vector(
        "feffe9928665731c6d6a8f9467308308",
        concat!(
            "d9313225f88406e5a55909c5aff5269a",
            "86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525",
            "b16aedf5aa0de657ba637b39"
        ),
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "cafebabefacedbaddecaf888",
        concat!(
            "42831ec2217774244b7221b784d0d49c",
            "e3aa212f2c02a4e035c17e2329aca12e",
            "21d514b25466931c7d8f6a5aac84aa05",
            "1ba30b396a0aac973d58e091"
        ),
        "5bc94fbc3221a5db94fae95ae7121a47",
    );
    check_vector(
        "feffe9928665731c6d6a8f9467308308",
        concat!(
            "d9313225f88406e5a55909c5aff5269a",
            "86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525",
            "b16aedf5aa0de657ba637b39"
        ),
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "cafebabefacedbaddecaf888",
        concat!(
            "42831ec2217774244b7221b784d0d49c",
            "e3aa212f2c02a4e035c17e2329aca12e",
            "21d514b25466931c7d8f6a5aac84aa05",
            "1ba30b396a0aac973d58e091"
        ),
        "5bc94fbc3221a5db94fae95a",
    );
    check_vector(
        "feffe9928665731c6d6a8f9467308308",
        concat!(
            "d9313225f88406e5a55909c5aff5269a",
            "86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525",
            "b16aedf5aa0de657ba637b39"
        ),
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "cafebabefacedbad",
        concat!(
            "61353b4c2806934a777ff51fa22a4755",
            "699b2a714fcdc6f83766e5f97b6c7423",
            "73806900e49f24b22b097544d4896b42",
            "4989b5e1ebac0f07c23f4598"
        ),
        "3612d2e79e3b0785561be14aaca2fccb",
    );
    check_vector(
        "feffe9928665731c6d6a8f9467308308",
        concat!(
            "d9313225f88406e5a55909c5aff5269a",
            "86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525",
            "b16aedf5aa0de657ba637b39"
        ),
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        concat!(
            "9313225df88406e555909c5aff5269aa",
            "6a7a9538534f7da1e4c303d2a318a728",
            "c3c0c95156809539fcf0e2429a6b5254",
            "16aedbf5a0de6a57a637b39b"
        ),
        concat!(
            "8ce24998625615b603a033aca13fb894",
            "be9112a5c3a211a8ba262a3cca7e2ca7",
            "01e4a9a4fba43c90ccdcb281d48c7c6f",
            "d62875d2aca417034c34aee5"
        ),
        "619cc5aefffe0bfa462af43c1699d050",
    );
    check_vector(
        "000000000000000000000000000000000000000000000000",
        "",
        "",
        "000000000000000000000000",
        "",
        "cd33b28ac773f74ba00ed1f312572435",
    );
    check_vector(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "",
        "",
        "000000000000000000000000",
        "",
        "530f8afbc74536b9a963b4f1c4cb738b",
    );
}

#[test]
fn chunked_aad_and_message_match_single_call() {
    let key = [0x11u8; 16];
    let nonce = [0x22u8; 11];
    let aad = [0x33u8; 37];
    let plaintext = [0x44u8; 91];
    let params = AeadBlockParams::new(&key, &nonce, 12, &[]);

    let mut expected_engine = GcmBlockCipher::new(AesEngine::new());
    expected_engine
        .init(CipherDirection::Encrypt, &params)
        .unwrap();
    expected_engine.process_aad_bytes(&aad).unwrap();
    let mut expected = [0u8; 103];
    let mut expected_len = expected_engine
        .process_bytes(&plaintext, &mut expected)
        .unwrap();
    expected_len += expected_engine
        .do_final(&mut expected[expected_len..])
        .unwrap();

    let mut actual_engine = GcmBlockCipher::new(AesEngine::new());
    actual_engine
        .init(CipherDirection::Encrypt, &params)
        .unwrap();
    for chunk in aad.chunks(5) {
        actual_engine.process_aad_bytes(chunk).unwrap();
    }
    let mut actual = [0u8; 103];
    let mut actual_len = 0;
    for chunk in plaintext.chunks(7) {
        actual_len += actual_engine
            .process_bytes(chunk, &mut actual[actual_len..])
            .unwrap();
    }
    actual_len += actual_engine.do_final(&mut actual[actual_len..]).unwrap();

    assert_eq!(actual_len, expected_len);
    assert_eq!(actual, expected);
}

#[test]
fn validates_parameters_nonce_reuse_aad_order_and_tag() {
    let key = [0x11u8; 16];
    let nonce = [0x22u8; 12];
    let params = AeadBlockParams::new(&key, &nonce, 12, b"header");
    let mut cipher = GcmBlockCipher::new(AesEngine::new());

    assert!(matches!(
        cipher.init(
            CipherDirection::Encrypt,
            &AeadBlockParams::new(&key, &[], 12, &[]),
        ),
        Err(AeadBlockInitError::InvalidNonceLength(0))
    ));
    assert!(matches!(
        cipher.init(
            CipherDirection::Encrypt,
            &AeadBlockParams::new(&key, &nonce, 3, &[]),
        ),
        Err(AeadBlockInitError::InvalidMacSize(3))
    ));

    cipher.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(cipher.process_bytes(b"secret", &mut []), Ok(0));
    assert_eq!(
        cipher.process_aad_bytes(b"late"),
        Err(AeadBlockError::Aead(AeadError::AadAfterData))
    );
    let mut encrypted = [0u8; 18];
    cipher.do_final(&mut encrypted).unwrap();
    assert!(matches!(
        cipher.init(CipherDirection::Encrypt, &params),
        Err(AeadBlockInitError::NonceReuse)
    ));

    encrypted[0] ^= 1;
    let mut decryptor = GcmBlockCipher::new(AesEngine::new());
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    assert_eq!(decryptor.process_bytes(&encrypted, &mut []), Ok(0));
    let mut output = [0xabu8; 6];
    assert_eq!(
        decryptor.do_final(&mut output),
        Err(AeadBlockError::Aead(AeadError::AuthenticationFailed))
    );
    assert_eq!(output, [0xab; 6]);
    assert_eq!(decryptor.mac(), None);
}

#[test]
fn exposes_metadata_sizes_and_reset_semantics() {
    let key = [0u8; 16];
    let nonce = [0u8; 12];
    let params = AeadBlockParams::new(&key, &nonce, 16, b"header");
    let mut cipher = GcmBlockCipher::new(AesEngine::new());
    let mut name = String::new();
    cipher.write_algo_name(&mut name).unwrap();
    assert_eq!(name, "AES/GCM");
    assert_eq!(cipher.block_size(), 16);
    assert_eq!(cipher.underlying_cipher().block_size(), 16);

    cipher.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(cipher.get_update_output_size(15), 0);
    assert_eq!(cipher.get_update_output_size(16), 16);
    assert_eq!(cipher.get_output_size(15), 31);
    cipher.reset();
    assert_eq!(cipher.get_output_size(0), 16);
    cipher.process_bytes(&[0u8; 1], &mut []).unwrap();
    cipher.reset();
    assert_eq!(
        cipher.process_bytes(&[], &mut []),
        Err(AeadBlockError::Aead(AeadError::AlreadyFinalised))
    );
}

#[test]
fn decrypt_reset_restores_initial_aad_and_discards_buffered_ciphertext() {
    let key = [0x11u8; 16];
    let nonce = [0x22u8; 12];
    let params = AeadBlockParams::new(&key, &nonce, 16, b"initial header");
    let plaintext = b"message";

    let mut encryptor = GcmBlockCipher::new(AesEngine::new());
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    let mut encrypted = [0u8; 23];
    let mut encrypted_len = encryptor.process_bytes(plaintext, &mut encrypted).unwrap();
    encrypted_len += encryptor.do_final(&mut encrypted[encrypted_len..]).unwrap();
    assert_eq!(encrypted_len, encrypted.len());

    let mut decryptor = GcmBlockCipher::new(AesEngine::new());
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    assert_eq!(decryptor.process_bytes(&encrypted[..5], &mut []), Ok(0));
    decryptor.reset();

    let mut recovered = [0u8; 7];
    let mut recovered_len = decryptor.process_bytes(&encrypted, &mut recovered).unwrap();
    recovered_len += decryptor.do_final(&mut recovered[recovered_len..]).unwrap();
    assert_eq!(recovered_len, plaintext.len());
    assert_eq!(&recovered, plaintext);
}

#[test]
fn short_update_output_does_not_consume_input() {
    let key = [0u8; 16];
    let nonce = [0u8; 12];
    let params = AeadBlockParams::new(&key, &nonce, 16, &[]);
    let plaintext = [0u8; 16];
    let mut cipher = GcmBlockCipher::new(AesEngine::new());
    cipher.init(CipherDirection::Encrypt, &params).unwrap();

    assert_eq!(
        cipher.process_bytes(&plaintext, &mut [0u8; 15]),
        Err(AeadBlockError::Aead(AeadError::OutputTooShort {
            required: 16,
            available: 15,
        }))
    );

    let mut encrypted = [0u8; 32];
    let mut written = cipher.process_bytes(&plaintext, &mut encrypted).unwrap();
    written += cipher.do_final(&mut encrypted[written..]).unwrap();
    assert_eq!(written, encrypted.len());
    assert_eq!(
        &encrypted[..16],
        &decode("0388dace60b6a392f328c2b971b2fe78")
    );
    assert_eq!(
        &encrypted[16..],
        &decode("ab6e47d42cec13bdf53a67b21257bddf")
    );
}
