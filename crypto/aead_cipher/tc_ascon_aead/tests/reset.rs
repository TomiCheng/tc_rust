use tc_ascon_aead::{aead128, legacy};
use tc_cipher::{AeadCipher, AeadCipherInit, AeadError, CipherDirection};

#[test]
fn aead128_reset_restores_decryption_with_initial_aad() {
    let key = [0x11; aead128::KEY_BYTES];
    let nonce = [0x22; aead128::NONCE_BYTES];
    let params = aead128::Params::new(&key, &nonce, b"initial aad");
    let plaintext = b"reset message";

    let mut encryptor = aead128::Engine::new();
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    let mut ciphertext = vec![0u8; plaintext.len() + aead128::TAG_BYTES];
    let mut written = encryptor.process_bytes(plaintext, &mut ciphertext).unwrap();
    written += encryptor.do_final(&mut ciphertext[written..]).unwrap();
    ciphertext.truncate(written);
    encryptor.reset();
    assert_eq!(encryptor.mac(), None);
    assert_eq!(
        encryptor.process_bytes(&[], &mut []),
        Err(AeadError::AlreadyFinalised)
    );

    let mut decryptor = aead128::Engine::new();
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    decryptor.process_aad_bytes(b"discarded").unwrap();
    assert_eq!(decryptor.process_bytes(&ciphertext[..5], &mut []), Ok(0));
    decryptor.reset();

    let mut recovered = vec![0u8; plaintext.len()];
    let mut recovered_len = decryptor
        .process_bytes(&ciphertext, &mut recovered)
        .unwrap();
    recovered_len += decryptor.do_final(&mut recovered[recovered_len..]).unwrap();
    assert_eq!(&recovered[..recovered_len], plaintext);
}

#[test]
fn legacy_reset_restores_decryption_with_initial_aad() {
    let key = [0x33; legacy::KEY_BYTES_128];
    let nonce = [0x44; legacy::NONCE_BYTES];
    let params = legacy::Params::new(&key, &nonce, b"initial aad");
    let plaintext = b"legacy reset";

    let mut encryptor = legacy::Engine::new(legacy::Variant::Ascon128a);
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    let mut ciphertext = vec![0u8; plaintext.len() + legacy::TAG_BYTES];
    let mut written = encryptor.process_bytes(plaintext, &mut ciphertext).unwrap();
    written += encryptor.do_final(&mut ciphertext[written..]).unwrap();
    ciphertext.truncate(written);

    let mut decryptor = legacy::Engine::new(legacy::Variant::Ascon128a);
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    decryptor.process_aad_bytes(b"discarded").unwrap();
    decryptor.reset();

    let mut recovered = vec![0u8; plaintext.len()];
    let mut recovered_len = decryptor
        .process_bytes(&ciphertext, &mut recovered)
        .unwrap();
    recovered_len += decryptor.do_final(&mut recovered[recovered_len..]).unwrap();
    assert_eq!(&recovered[..recovered_len], plaintext);
}
