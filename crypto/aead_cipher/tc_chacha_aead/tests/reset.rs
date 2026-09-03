use tc_chacha_aead::{
    ChaCha20Poly1305, KEY_BYTES, NONCE_BYTES, Params, TAG_BYTES, XChaCha20Poly1305, XNONCE_BYTES,
};
use tc_cipher::{AeadCipher, AeadCipherInit, AeadError, CipherDirection};

#[test]
fn reset_restores_chacha_decryption_with_initial_aad() {
    let key = [0x11; KEY_BYTES];
    let nonce = [0x22; NONCE_BYTES];
    let params = Params::new(&key, &nonce, b"initial aad");
    let plaintext = b"chacha reset";
    let mut encryptor = ChaCha20Poly1305::new();
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    let mut ciphertext = vec![0u8; plaintext.len() + TAG_BYTES];
    let mut written = encryptor.process_bytes(plaintext, &mut ciphertext).unwrap();
    written += encryptor.do_final(&mut ciphertext[written..]).unwrap();
    ciphertext.truncate(written);
    encryptor.reset();
    assert_eq!(
        encryptor.process_bytes(&[], &mut []),
        Err(AeadError::AlreadyFinalised)
    );

    let mut decryptor = ChaCha20Poly1305::new();
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    decryptor.process_aad_bytes(b"discarded").unwrap();
    decryptor.process_bytes(&ciphertext[..5], &mut []).unwrap();
    decryptor.reset();

    let mut recovered = vec![0u8; plaintext.len()];
    let mut recovered_len = decryptor
        .process_bytes(&ciphertext, &mut recovered)
        .unwrap();
    recovered_len += decryptor.do_final(&mut recovered[recovered_len..]).unwrap();
    assert_eq!(&recovered[..recovered_len], plaintext);
}

#[test]
fn xchacha_reset_restores_decryption() {
    let key = [0x33; KEY_BYTES];
    let nonce = [0x44; XNONCE_BYTES];
    let params = Params::new(&key, &nonce, b"initial aad");
    let plaintext = b"xchacha reset";
    let mut encryptor = XChaCha20Poly1305::new();
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    let mut ciphertext = vec![0u8; plaintext.len() + TAG_BYTES];
    let mut written = encryptor.process_bytes(plaintext, &mut ciphertext).unwrap();
    written += encryptor.do_final(&mut ciphertext[written..]).unwrap();
    ciphertext.truncate(written);

    let mut decryptor = XChaCha20Poly1305::new();
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
