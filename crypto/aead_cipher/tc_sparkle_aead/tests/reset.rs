use tc_cipher::{AeadCipher, AeadCipherInit, AeadError, CipherDirection};
use tc_sparkle_aead::{Engine, Params, Variant};

#[test]
fn reset_restores_decryption_with_initial_aad_and_blocks_encryption_reuse() {
    let variant = Variant::Schwaemm128_128;
    let key = [0x11; 16];
    let nonce = [0x22; 16];
    let params = Params::new(&key, &nonce, b"initial aad");
    let plaintext = b"sparkle reset";

    let mut encryptor = Engine::new(variant);
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    let mut ciphertext = vec![0u8; plaintext.len() + variant.tag_bytes()];
    let mut written = encryptor.process_bytes(plaintext, &mut ciphertext).unwrap();
    written += encryptor.do_final(&mut ciphertext[written..]).unwrap();
    ciphertext.truncate(written);
    encryptor.reset();
    assert_eq!(encryptor.mac(), None);
    assert_eq!(
        encryptor.process_bytes(&[], &mut []),
        Err(AeadError::AlreadyFinalised)
    );

    let mut decryptor = Engine::new(variant);
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
