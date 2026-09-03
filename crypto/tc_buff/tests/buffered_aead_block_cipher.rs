use tc_aes::AesEngine;
use tc_buff::BufferedAeadBlockCipher;
use tc_ccm::CcmBlockCipher;
use tc_cipher::{BufferedCipher, BufferedCipherInit, CipherDirection};
use tc_params::AeadBlockParams;

#[test]
fn ccm_reports_block_size_resets_and_round_trips() {
    let key = [0x11; 16];
    let nonce = [0x22; 12];
    let params = AeadBlockParams::new(&key, &nonce, 16, b"header");
    let plaintext = b"message";

    let mut encryptor = BufferedAeadBlockCipher::new(CcmBlockCipher::new(AesEngine::new()));
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(encryptor.block_size(), 16);

    assert_eq!(encryptor.process_byte(0xff, &mut []).unwrap(), 0);
    encryptor.reset();
    assert_eq!(encryptor.process_bytes(plaintext, &mut []).unwrap(), 0);
    let mut encrypted = [0u8; 7 + 16];
    let encrypted_len = encryptor.do_final(&mut encrypted).unwrap();
    assert_eq!(encrypted_len, encrypted.len());

    let mut decryptor = BufferedAeadBlockCipher::new(CcmBlockCipher::new(AesEngine::new()));
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    assert_eq!(decryptor.process_bytes(&encrypted, &mut []).unwrap(), 0);
    let mut recovered = [0u8; 7];
    let recovered_len = decryptor.do_final(&mut recovered).unwrap();

    assert_eq!(recovered_len, plaintext.len());
    assert_eq!(&recovered, plaintext);
}
