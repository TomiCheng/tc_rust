use tc_cipher::{AeadCipher, AeadCipherInit, AeadError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_grain128_aead::{Engine, KEY_BYTES, NONCE_BYTES, TAG_BYTES};
use tc_params::{AadLengthParams, InitialAadParams, IvParams, KeyParams};

struct Params<'a> {
    key: &'a [u8],
    iv: &'a [u8],
    initial_aad: &'a [u8],
    aad_len: usize,
}

impl<'a> Params<'a> {
    const fn new(key: &'a [u8], iv: &'a [u8], initial_aad: &'a [u8], aad_len: usize) -> Self {
        Self {
            key,
            iv,
            initial_aad,
            aad_len,
        }
    }
}

impl KeyParams for Params<'_> {
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl IvParams for Params<'_> {
    fn iv(&self) -> &[u8] {
        self.iv
    }
}

impl InitialAadParams for Params<'_> {
    fn initial_aad(&self) -> &[u8] {
        self.initial_aad
    }
}

impl AadLengthParams for Params<'_> {
    fn aad_len(&self) -> usize {
        self.aad_len
    }
}

fn algo_name(engine: &Engine) -> String {
    let mut name = String::new();
    engine.write_algo_name(&mut name).unwrap();
    name
}

struct Kat {
    plaintext: &'static str,
    aad: &'static str,
    ciphertext_and_tag: &'static str,
}

const KEY: &str = "000102030405060708090A0B0C0D0E0F";
const NONCE: &str = "000102030405060708090A0B";

const KATS: &[Kat] = &[
    Kat {
        plaintext: "",
        aad: "",
        ciphertext_and_tag: "D51FD5D16177B434",
    },
    Kat {
        plaintext: "",
        aad: "00",
        ciphertext_and_tag: "99B7CDBF488F8DC0",
    },
    Kat {
        plaintext: "00",
        aad: "",
        ciphertext_and_tag: "21AAA5A068EA941DB3",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F",
        aad: "",
        ciphertext_and_tag: "21678706FB8AB6369ED9B5AFA619F8B27DEA6B6B907BE8FF",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F",
        aad: "000102030405060708090A0B0C0D0E0F",
        ciphertext_and_tag: "80B53BE28E938BAE76B64CCD53BE4DE5FB0720DE18EA8FAE",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        aad: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        ciphertext_and_tag: "D70DF45E4839CFF9A2C139C719805CFCAAB5AB651B99A751FBF4B8D75ABD6D97F543FE1CFBE56F72",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        aad: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9",
        ciphertext_and_tag: "731DAA8B1D15317A1CCB4E3DD320095FB27E5BB2A10F2C669F870538637D4F162298C70430A2B560",
    },
];

fn decode_hex(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn material() -> (Vec<u8>, Vec<u8>) {
    (decode_hex(KEY), decode_hex(NONCE))
}

fn encrypt(plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let (key, nonce) = material();
    let params = Params::new(&key, &nonce, aad, aad.len());
    let mut engine = Engine::new();
    engine.init(CipherDirection::Encrypt, &params).unwrap();
    let mut output = vec![0xA5; engine.get_output_size(plaintext.len())];
    let mut written = engine.process_bytes(plaintext, &mut output).unwrap();
    written += engine.do_final(&mut output[written..]).unwrap();
    output.truncate(written);
    output
}

fn decrypt(ciphertext: &[u8], aad: &[u8]) -> Vec<u8> {
    let (key, nonce) = material();
    let params = Params::new(&key, &nonce, aad, aad.len());
    let mut engine = Engine::new();
    engine.init(CipherDirection::Decrypt, &params).unwrap();
    let mut output = vec![0xA5; engine.get_output_size(ciphertext.len())];
    let mut written = engine.process_bytes(ciphertext, &mut output).unwrap();
    written += engine.do_final(&mut output[written..]).unwrap();
    output.truncate(written);
    output
}

#[test]
fn matches_official_and_bc_csharp_vectors() {
    for kat in KATS {
        let plaintext = decode_hex(kat.plaintext);
        let aad = decode_hex(kat.aad);
        let expected = decode_hex(kat.ciphertext_and_tag);
        assert_eq!(encrypt(&plaintext, &aad), expected);
        assert_eq!(decrypt(&expected, &aad), plaintext);
    }
}

#[test]
fn declared_aad_length_supports_incremental_aad_and_data() {
    let kat = &KATS[5];
    let plaintext = decode_hex(kat.plaintext);
    let aad = decode_hex(kat.aad);
    let expected = decode_hex(kat.ciphertext_and_tag);
    let (key, nonce) = material();

    for split in 0..=plaintext.len() {
        let params = Params::new(&key, &nonce, &[], aad.len());
        let mut engine = Engine::new();
        engine.init(CipherDirection::Encrypt, &params).unwrap();
        engine.process_aad_bytes(&aad[..7]).unwrap();
        engine.process_aad_bytes(&aad[7..]).unwrap();

        let mut output = vec![0_u8; expected.len()];
        let mut written = engine
            .process_bytes(&plaintext[..split], &mut output)
            .unwrap();
        written += engine
            .process_bytes(&plaintext[split..], &mut output[written..])
            .unwrap();
        written += engine.do_final(&mut output[written..]).unwrap();
        assert_eq!(&output[..written], expected);
    }

    for split in 0..=expected.len() {
        let params = Params::new(&key, &nonce, &[], aad.len());
        let mut engine = Engine::new();
        engine.init(CipherDirection::Decrypt, &params).unwrap();
        engine.process_aad_bytes(&aad[..15]).unwrap();
        engine.process_aad_bytes(&aad[15..]).unwrap();

        let mut output = vec![0_u8; plaintext.len()];
        let mut written = engine
            .process_bytes(&expected[..split], &mut output)
            .unwrap();
        written += engine
            .process_bytes(&expected[split..], &mut output[written..])
            .unwrap();
        written += engine.do_final(&mut output[written..]).unwrap();
        assert_eq!(&output[..written], plaintext);
    }
}

#[test]
fn enforces_declared_aad_length() {
    let (key, nonce) = material();
    let params = Params::new(&key, &nonce, &[], 3);
    let mut engine = Engine::new();
    engine.init(CipherDirection::Encrypt, &params).unwrap();
    engine.process_aad_bytes(&[1, 2]).unwrap();
    assert_eq!(
        engine.process_bytes(&[], &mut []),
        Err(AeadError::AadLengthMismatch {
            expected: 3,
            actual: 2,
        })
    );
    assert_eq!(
        engine.process_aad_bytes(&[3, 4]),
        Err(AeadError::AadLengthMismatch {
            expected: 3,
            actual: 4,
        })
    );
    engine.process_aad_bytes(&[3]).unwrap();
    assert_eq!(engine.do_final(&mut [0_u8; TAG_BYTES]), Ok(TAG_BYTES));
}

#[test]
fn rejects_invalid_initialization_lengths() {
    let (key, nonce) = material();
    let mut engine = Engine::new();

    let params = Params::new(&key[..KEY_BYTES - 1], &nonce, &[], 0);
    assert_eq!(
        engine.init(CipherDirection::Encrypt, &params),
        Err(InitError::InvalidKeyLength(KEY_BYTES - 1))
    );

    let params = Params::new(&key, &nonce[..NONCE_BYTES - 1], &[], 0);
    assert_eq!(
        engine.init(CipherDirection::Encrypt, &params),
        Err(InitError::InvalidIvLength(NONCE_BYTES - 1))
    );

    let params = Params::new(&key, &nonce, &[1, 2], 1);
    assert_eq!(
        engine.init(CipherDirection::Encrypt, &params),
        Err(InitError::InvalidAadLength {
            expected: 1,
            actual: 2,
        })
    );
}

#[test]
fn rejects_modified_tags_and_short_ciphertexts() {
    let kat = KATS.last().unwrap();
    let aad = decode_hex(kat.aad);
    let mut ciphertext = decode_hex(kat.ciphertext_and_tag);
    *ciphertext.last_mut().unwrap() ^= 1;
    let (key, nonce) = material();
    let params = Params::new(&key, &nonce, &aad, aad.len());
    let mut engine = Engine::new();
    engine.init(CipherDirection::Decrypt, &params).unwrap();
    let mut output = vec![0xA5; engine.get_output_size(ciphertext.len())];
    let written = engine.process_bytes(&ciphertext, &mut output).unwrap();
    assert_eq!(
        engine.do_final(&mut output[written..]),
        Err(AeadError::AuthenticationFailed)
    );
    assert_eq!(engine.mac(), None);

    let params = Params::new(&key, &nonce, &[], 0);
    engine.init(CipherDirection::Decrypt, &params).unwrap();
    assert_eq!(engine.process_bytes(&[0_u8; TAG_BYTES - 1], &mut []), Ok(0));
    assert_eq!(
        engine.do_final(&mut []),
        Err(AeadError::CiphertextTooShort {
            minimum: TAG_BYTES,
            actual: TAG_BYTES - 1,
        })
    );
}

#[test]
fn reports_metadata_and_enforces_state_and_buffer_rules() {
    let (key, nonce) = material();
    let params = Params::new(&key, &nonce, &[], 0);
    let mut engine = Engine::new();
    assert_eq!(algo_name(&engine), "Grain-128AEAD");
    assert_eq!(engine.key_bytes(), KEY_BYTES);
    assert_eq!(engine.nonce_bytes(), NONCE_BYTES);
    assert_eq!(engine.tag_bytes(), TAG_BYTES);
    assert_eq!(engine.get_update_output_size(5), 5);
    assert_eq!(engine.get_output_size(5), 5 + TAG_BYTES);
    assert_eq!(
        engine.process_bytes(&[], &mut []),
        Err(AeadError::NotInitialised)
    );

    engine.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(
        engine.process_bytes(&[0_u8; 5], &mut [0_u8; 4]),
        Err(AeadError::OutputTooShort {
            required: 5,
            available: 4,
        })
    );
    assert_eq!(engine.process_bytes(&[0_u8; 5], &mut [0_u8; 5]), Ok(5));
    assert_eq!(engine.process_aad_bytes(&[0]), Err(AeadError::AadAfterData));
    let mut tag = [0_u8; TAG_BYTES];
    assert_eq!(engine.do_final(&mut tag), Ok(TAG_BYTES));
    assert_eq!(engine.mac(), Some(tag.as_slice()));
    assert_eq!(engine.do_final(&mut []), Err(AeadError::AlreadyFinalised));
}
