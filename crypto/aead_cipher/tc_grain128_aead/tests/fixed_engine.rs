use tc_cipher::{AeadCipher, AeadCipherInit, AeadError, CipherDirection, InitError};
use tc_grain128_aead::{FixedEngine, KEY_BYTES, NONCE_BYTES, Params, TAG_BYTES};

#[test]
fn matches_official_vector_with_incremental_aad() {
    let key = core::array::from_fn::<_, KEY_BYTES, _>(|index| index as u8);
    let nonce = core::array::from_fn::<_, NONCE_BYTES, _>(|index| index as u8);
    let aad = core::array::from_fn::<_, 16, _>(|index| index as u8);
    let plaintext = core::array::from_fn::<_, 16, _>(|index| index as u8);
    let params = Params::new(&key, &nonce, &[]);
    let mut engine = FixedEngine::<16>::new();

    engine.init(CipherDirection::Encrypt, &params).unwrap();
    engine.process_aad_bytes(&aad[..7]).unwrap();
    engine.process_aad_bytes(&aad[7..]).unwrap();

    let mut output = [0_u8; 16 + TAG_BYTES];
    let mut written = engine.process_bytes(&plaintext, &mut output).unwrap();
    written += engine.do_final(&mut output[written..]).unwrap();

    assert_eq!(written, output.len());
    assert_eq!(
        output,
        [
            0x80, 0xB5, 0x3B, 0xE2, 0x8E, 0x93, 0x8B, 0xAE, 0x76, 0xB6, 0x4C, 0xCD, 0x53, 0xBE,
            0x4D, 0xE5, 0xFB, 0x07, 0x20, 0xDE, 0x18, 0xEA, 0x8F, 0xAE,
        ]
    );
}

#[test]
fn rejects_aad_beyond_fixed_capacity() {
    let key = [0_u8; KEY_BYTES];
    let nonce = [0_u8; NONCE_BYTES];
    let params = Params::new(&key, &nonce, &[]);
    let mut engine = FixedEngine::<3>::new();

    engine.init(CipherDirection::Encrypt, &params).unwrap();
    engine.process_aad_bytes(&[1, 2]).unwrap();
    assert_eq!(
        engine.process_aad_bytes(&[3, 4]),
        Err(AeadError::AadTooLong {
            maximum: 3,
            actual: 4,
        })
    );
}

#[test]
fn rejects_initial_aad_beyond_fixed_capacity() {
    let key = [0_u8; KEY_BYTES];
    let nonce = [0_u8; NONCE_BYTES];
    let params = Params::new(&key, &nonce, &[1, 2]);
    let mut engine = FixedEngine::<1>::new();

    assert_eq!(
        engine.init(CipherDirection::Encrypt, &params),
        Err(InitError::InitialAadTooLong {
            maximum: 1,
            actual: 2,
        })
    );
}
