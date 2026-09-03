#![cfg(feature = "alloc")]

use tc_aes::AesEngine;
use tc_cipher::{
    AeadBlockCipher, AeadBlockError, AeadCipher, AeadCipherInit, AeadError, BlockCipher,
    CipherDirection,
};
use tc_crypto::AlgorithmName;
use tc_eax::{EaxBlockCipher, EaxInitError};
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
    nonce_hex: &str,
    aad_hex: &str,
    plaintext_hex: &str,
    mac_size: usize,
    expected_hex: &str,
) {
    let key = decode(key_hex);
    let nonce = decode(nonce_hex);
    let aad = decode(aad_hex);
    let plaintext = decode(plaintext_hex);
    let expected = decode(expected_hex);
    let aad_split = aad.len() / 2;
    let params = AeadBlockParams::new(&key, &nonce, mac_size, &aad[..aad_split]);

    let mut encryptor = EaxBlockCipher::new(AesEngine::new());
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    encryptor.process_aad_bytes(&aad[aad_split..]).unwrap();
    let mut encrypted = vec![0u8; encryptor.get_output_size(plaintext.len())];
    let mut written = 0;
    for chunk in plaintext.chunks(3) {
        written += encryptor
            .process_bytes(chunk, &mut encrypted[written..])
            .unwrap();
    }
    written += encryptor.do_final(&mut encrypted[written..]).unwrap();
    assert_eq!(written, expected.len());
    assert_eq!(encrypted, expected);
    assert_eq!(
        encryptor.mac(),
        Some(&expected[expected.len() - mac_size..])
    );

    let mut decryptor = EaxBlockCipher::new(AesEngine::new());
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    decryptor.process_aad_bytes(&aad[aad_split..]).unwrap();
    let mut recovered = vec![0u8; decryptor.get_output_size(encrypted.len())];
    let mut recovered_len = 0;
    for chunk in encrypted.chunks(5) {
        recovered_len += decryptor
            .process_bytes(chunk, &mut recovered[recovered_len..])
            .unwrap();
    }
    recovered_len += decryptor.do_final(&mut recovered[recovered_len..]).unwrap();
    assert_eq!(recovered_len, plaintext.len());
    assert_eq!(recovered, plaintext);
    assert_eq!(
        decryptor.mac(),
        Some(&expected[expected.len() - mac_size..])
    );
}

#[test]
fn matches_bouncy_castle_vectors() {
    check_vector(
        "233952DEE4D5ED5F9B9C6D6FF80FF478",
        "62EC67F9C3A4A407FCB2A8C49031A8B3",
        "6BFB914FD07EAE6B",
        "",
        16,
        "E037830E8389F27B025A2D6527E79D01",
    );
    check_vector(
        "91945D3F4DCBEE0BF45EF52255F095A4",
        "BECAF043B0A23D843194BA972C66DEBD",
        "FA3BFD4806EB53FA",
        "F7FB",
        16,
        "19DD5C4C9331049D0BDAB0277408F67967E5",
    );
    check_vector(
        "01F74AD64077F2E704C0F60ADA3DD523",
        "70C3DB4F0D26368400A10ED05D2BFF5E",
        "234A3463C1264AC6",
        "1A47CB4933",
        16,
        "D851D5BAE03A59F238A23E39199DC9266626C40F80",
    );
    check_vector(
        "7C77D6E813BED5AC98BAA417477A2E7D",
        "1A8C98DCD73D38393B2BF1569DEEFC19",
        "65D2017990D62528",
        "8B0A79306C9CE7ED99DAE4F87F8DD61636",
        16,
        "02083E3979DA014812F59F11D52630DA30137327D10649B0AA6E1C181DB617D7F2",
    );
    check_vector(
        "8395FCF1E95BEBD697BD010BC766AAC3",
        "22E7ADD93CFC6393C57EC0B3C17D6B44",
        "126735FCC320D25A",
        "CA40D7446E545FFAED3BD12A740A659FFBBB3CEAB7",
        4,
        "CB8920F87A6C75CFF39627B56E3ED197C552D295A7CFC46AFC",
    );
}

#[test]
fn validates_parameters_order_nonce_reuse_and_tag() {
    let key = [0x11u8; 16];
    let nonce = [0x22u8; 12];
    let params = AeadBlockParams::new(&key, &nonce, 12, b"header");
    let mut cipher = EaxBlockCipher::new(AesEngine::new());

    assert!(matches!(
        cipher.init(
            CipherDirection::Encrypt,
            &AeadBlockParams::new(&key, &nonce, 3, &[]),
        ),
        Err(EaxInitError::InvalidMacSize(3))
    ));
    cipher.init(CipherDirection::Encrypt, &params).unwrap();
    cipher.process_bytes(b"message", &mut []).unwrap();
    assert_eq!(
        cipher.process_aad_bytes(b"late"),
        Err(AeadBlockError::Aead(AeadError::AadAfterData))
    );
    let mut encrypted = [0u8; 19];
    cipher.do_final(&mut encrypted).unwrap();
    assert!(matches!(
        cipher.init(CipherDirection::Encrypt, &params),
        Err(EaxInitError::NonceReuse)
    ));

    encrypted[0] ^= 1;
    let mut decryptor = EaxBlockCipher::new(AesEngine::new());
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    assert_eq!(decryptor.process_bytes(&encrypted, &mut [0u8; 7]), Ok(0));
    let mut output = [0xabu8; 7];
    assert_eq!(
        decryptor.do_final(&mut output),
        Err(AeadBlockError::Aead(AeadError::AuthenticationFailed))
    );
    assert_eq!(output, [0xab; 7]);
    assert_eq!(decryptor.mac(), None);
}

#[test]
fn exposes_metadata_sizes_and_reset_semantics() {
    let key = [0x11u8; 16];
    let nonce = [0x22u8; 12];
    let params = AeadBlockParams::new(&key, &nonce, 8, b"header");
    let mut cipher = EaxBlockCipher::new(AesEngine::new());
    let mut name = String::new();
    cipher.write_algo_name(&mut name).unwrap();
    assert_eq!(name, "AES/EAX");
    assert_eq!(cipher.block_size(), 16);
    assert_eq!(cipher.underlying_cipher().block_size(), 16);

    cipher.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(cipher.get_update_output_size(15), 0);
    assert_eq!(cipher.get_update_output_size(16), 16);
    assert_eq!(cipher.get_output_size(15), 23);
    cipher.process_bytes(b"discard", &mut []).unwrap();
    cipher.reset();

    let mut first = [0u8; 8];
    cipher.do_final(&mut first).unwrap();
    assert_eq!(cipher.mac(), Some(first.as_slice()));
    let mut second = [0u8; 8];
    cipher.do_final(&mut second).unwrap();
    assert_eq!(first, second);
}

#[test]
fn supports_every_whole_byte_aes_tag_size() {
    let key = [0x11u8; 16];
    let nonce = [0x22u8; 9];
    let plaintext = b"a message spanning more than one AES block";

    for mac_size in 4..=16 {
        let params = AeadBlockParams::new(&key, &nonce, mac_size, b"aad");
        let mut encryptor = EaxBlockCipher::new(AesEngine::new());
        encryptor.init(CipherDirection::Encrypt, &params).unwrap();
        let mut encrypted = vec![0u8; encryptor.get_output_size(plaintext.len())];
        let mut written = encryptor.process_bytes(plaintext, &mut encrypted).unwrap();
        written += encryptor.do_final(&mut encrypted[written..]).unwrap();
        assert_eq!(written, plaintext.len() + mac_size);

        let mut decryptor = EaxBlockCipher::new(AesEngine::new());
        decryptor.init(CipherDirection::Decrypt, &params).unwrap();
        let mut recovered = vec![0u8; plaintext.len()];
        let mut recovered_len = decryptor.process_bytes(&encrypted, &mut recovered).unwrap();
        recovered_len += decryptor.do_final(&mut recovered[recovered_len..]).unwrap();
        assert_eq!(recovered_len, plaintext.len());
        assert_eq!(recovered, plaintext);
    }
}
