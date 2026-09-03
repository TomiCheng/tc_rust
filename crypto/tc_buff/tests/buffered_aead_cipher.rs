use tc_ascon_aead::aead128::{Engine, KEY_BYTES, NONCE_BYTES, Params, TAG_BYTES};
use tc_buff::BufferedAeadCipher;
use tc_cipher::{BufferedCipher, BufferedCipherInit, BufferedError, CipherDirection};

#[test]
fn ascon_round_trips_chunked_input() {
    let key = [0x11; KEY_BYTES];
    let nonce = [0x22; NONCE_BYTES];
    let params = Params::new(&key, &nonce, b"header");
    let plaintext = b"buffered AEAD message";

    let mut encryptor = BufferedAeadCipher::new(Engine::new());
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(encryptor.block_size(), 0);

    let mut encrypted = [0u8; 21 + TAG_BYTES];
    let mut encrypted_len = encryptor
        .process_byte(plaintext[0], &mut encrypted)
        .unwrap();
    encrypted_len += encryptor
        .process_bytes(&plaintext[1..], &mut encrypted[encrypted_len..])
        .unwrap();
    encrypted_len += encryptor.do_final(&mut encrypted[encrypted_len..]).unwrap();
    assert_eq!(encrypted_len, encrypted.len());

    let mut decryptor = BufferedAeadCipher::new(Engine::new());
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    let mut recovered = [0u8; 21];
    let mut recovered_len = decryptor.process_bytes(&encrypted, &mut recovered).unwrap();
    recovered_len += decryptor.do_final(&mut recovered[recovered_len..]).unwrap();

    assert_eq!(recovered_len, plaintext.len());
    assert_eq!(&recovered, plaintext);
}

#[test]
fn reports_use_before_initialization() {
    let mut cipher = BufferedAeadCipher::new(Engine::new());

    assert!(matches!(
        cipher.process_byte(0, &mut []),
        Err(BufferedError::NotInitialised)
    ));
    assert!(matches!(
        cipher.process_bytes(&[], &mut []),
        Err(BufferedError::NotInitialised)
    ));
    assert!(matches!(
        cipher.do_final(&mut []),
        Err(BufferedError::NotInitialised)
    ));
}

#[test]
fn rejects_short_output_without_consuming_input() {
    let key = [0x11; KEY_BYTES];
    let nonce = [0x22; NONCE_BYTES];
    let params = Params::new(&key, &nonce, &[]);
    let input = [0x33; 16];
    let mut cipher = BufferedAeadCipher::new(Engine::new());
    cipher.init(CipherDirection::Encrypt, &params).unwrap();

    assert_eq!(
        cipher.process_bytes(&input, &mut [0u8; 15]),
        Err(BufferedError::OutputTooShort {
            required: 16,
            available: 15,
        })
    );

    let mut output = [0u8; 16];
    assert_eq!(cipher.process_bytes(&input, &mut output), Ok(16));
}
