use tc_aes::AesEngine;
use tc_buff::BufferedBlockCipher;
use tc_cfb::CfbBlockCipher;
use tc_cipher::{BufferedCipher, BufferedCipherInit, BufferedError, CipherDirection};
use tc_params::{KeyRef, KeyWithIvRef};

const KEY: [u8; 16] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];
const IV: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

#[test]
fn bare_block_cipher_buffers_arbitrary_chunks() {
    let plaintext = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a,
    ];
    let expected = [
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef,
        0x97,
    ];
    let params = KeyRef::new(&KEY);
    let mut cipher = BufferedBlockCipher::from_cipher(AesEngine::new());
    cipher.init(CipherDirection::Encrypt, &params).unwrap();

    let mut output = [0u8; 16];
    assert_eq!(cipher.process_bytes(&plaintext[..5], &mut output), Ok(0));
    assert_eq!(cipher.process_bytes(&plaintext[5..15], &mut []), Ok(0));
    assert_eq!(cipher.get_update_output_size(1), 16);
    assert_eq!(cipher.process_byte(plaintext[15], &mut output), Ok(16));
    assert_eq!(cipher.do_final(&mut []), Ok(0));
    assert_eq!(output, expected);

    cipher.init(CipherDirection::Decrypt, &params).unwrap();
    let mut recovered = [0u8; 16];
    assert_eq!(cipher.process_bytes(&output, &mut recovered), Ok(16));
    assert_eq!(cipher.do_final(&mut []), Ok(0));
    assert_eq!(recovered, plaintext);
}

#[test]
fn aligned_mode_rejects_a_partial_final_block_and_resets() {
    let mut cipher = BufferedBlockCipher::from_cipher(AesEngine::new());
    cipher
        .init(CipherDirection::Encrypt, &KeyRef::new(&KEY))
        .unwrap();

    assert_eq!(cipher.process_bytes(&[1, 2, 3], &mut []), Ok(0));
    assert!(matches!(
        cipher.do_final(&mut [0u8; 3]),
        Err(BufferedError::IncompleteLastBlock)
    ));
    assert_eq!(cipher.get_output_size(0), 0);
}

#[test]
fn stream_oriented_mode_emits_a_partial_final_block() {
    let plaintext = [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f];
    let expected = [0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad];
    let params = KeyWithIvRef::new(&KEY, &IV);
    let mode = CfbBlockCipher::new(AesEngine::new(), 128).unwrap();
    let mut cipher = BufferedBlockCipher::new(mode);
    cipher.init(CipherDirection::Encrypt, &params).unwrap();

    let mut encrypted = [0u8; 7];
    assert_eq!(cipher.process_bytes(&plaintext, &mut encrypted), Ok(0));
    assert_eq!(cipher.do_final(&mut encrypted), Ok(7));
    assert_eq!(encrypted, expected);

    cipher.init(CipherDirection::Decrypt, &params).unwrap();
    let mut recovered = [0u8; 7];
    assert_eq!(cipher.process_bytes(&encrypted, &mut recovered), Ok(0));
    assert_eq!(cipher.do_final(&mut recovered), Ok(7));
    assert_eq!(recovered, plaintext);
}

#[test]
fn rejects_short_output_before_consuming_input() {
    let mut cipher = BufferedBlockCipher::from_cipher(AesEngine::new());
    cipher
        .init(CipherDirection::Encrypt, &KeyRef::new(&KEY))
        .unwrap();

    assert_eq!(
        cipher.process_bytes(&[0u8; 16], &mut [0u8; 15]),
        Err(BufferedError::OutputTooShort {
            required: 16,
            available: 15,
        })
    );
    assert_eq!(cipher.get_output_size(0), 0);
}
