use tc_buff::BufferedStreamCipher;
use tc_cipher::{BufferedCipher, BufferedCipherInit, BufferedError, CipherDirection};
use tc_params::KeyRef;
use tc_rc4::Rc4Engine;

const EXPECTED: [u8; 9] = [0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3];

#[test]
fn rc4_processes_each_byte_immediately_and_round_trips() {
    let params = KeyRef::new(b"Key");
    let mut cipher = BufferedStreamCipher::new(Rc4Engine::new());
    cipher.init(CipherDirection::Encrypt, &params).unwrap();

    assert_eq!(cipher.block_size(), 0);
    assert_eq!(cipher.get_update_output_size(9), 9);
    assert_eq!(cipher.get_output_size(9), 9);

    let mut encrypted = [0u8; 9];
    assert_eq!(cipher.process_byte(b'P', &mut encrypted[..1]), Ok(1));
    assert_eq!(
        cipher.process_bytes(&b"Plaintext"[1..], &mut encrypted[1..]),
        Ok(8)
    );
    assert_eq!(encrypted, EXPECTED);

    assert_eq!(cipher.do_final(&mut []), Ok(0));
    let mut repeated = [0u8; 9];
    assert_eq!(cipher.process_bytes(b"Plaintext", &mut repeated), Ok(9));
    assert_eq!(repeated, EXPECTED);

    cipher.init(CipherDirection::Decrypt, &params).unwrap();
    let mut recovered = [0u8; 9];
    assert_eq!(cipher.process_bytes(&encrypted, &mut recovered), Ok(9));
    assert_eq!(recovered, *b"Plaintext");
}

#[test]
fn rejects_short_output_without_advancing_the_keystream() {
    let mut cipher = BufferedStreamCipher::new(Rc4Engine::new());
    cipher
        .init(CipherDirection::Encrypt, &KeyRef::new(b"Key"))
        .unwrap();

    assert_eq!(
        cipher.process_bytes(b"Plaintext", &mut [0u8; 8]),
        Err(BufferedError::OutputTooShort {
            required: 9,
            available: 8,
        })
    );

    let mut output = [0u8; 9];
    assert_eq!(cipher.process_bytes(b"Plaintext", &mut output), Ok(9));
    assert_eq!(output, EXPECTED);
}

#[test]
fn reports_use_before_initialization() {
    let mut cipher = BufferedStreamCipher::new(Rc4Engine::new());

    assert!(matches!(
        cipher.process_byte(0, &mut [0u8; 1]),
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
