use tc_aead_cipher::{
    AeadCipherError,
    ascon_aead128::{BorrowedParams, Engine, Params},
};
use tc_cipher_core::{AeadCipher, AeadCipherInit, CipherDirection};

struct Kat {
    plaintext: &'static str,
    aad: &'static str,
    ciphertext_and_tag: &'static str,
}

struct OwnedParams {
    key: [u8; 16],
    nonce: [u8; 16],
    initial_aad: Vec<u8>,
}

impl Params for OwnedParams {
    fn key(&self) -> &[u8; 16] {
        &self.key
    }

    fn nonce(&self) -> &[u8; 16] {
        &self.nonce
    }

    fn initial_aad(&self) -> &[u8] {
        &self.initial_aad
    }
}

const KEY: &str = "000102030405060708090A0B0C0D0E0F";
const NONCE: &str = "101112131415161718191A1B1C1D1E1F";

// Official ascon-c Ascon-AEAD128 KATs covering empty, 8/15/16/17-byte
// boundaries, and multi-block input.
const KATS: &[Kat] = &[
    Kat {
        plaintext: "",
        aad: "",
        ciphertext_and_tag: "4F9C278211BEC9316BF68F46EE8B2EC6",
    },
    Kat {
        plaintext: "",
        aad: "3031323334353637",
        ciphertext_and_tag: "865C594093A9EDEE2C1D6384CCB4939E",
    },
    Kat {
        plaintext: "",
        aad: "303132333435363738393A3B3C3D3E",
        ciphertext_and_tag: "759102A6953861627AAE1836D003A294",
    },
    Kat {
        plaintext: "",
        aad: "303132333435363738393A3B3C3D3E3F",
        ciphertext_and_tag: "E4230CDB8330EE9DC0CFD7C7B346E6DC",
    },
    Kat {
        plaintext: "",
        aad: "303132333435363738393A3B3C3D3E3F40",
        ciphertext_and_tag: "BD8851CD3AF9847844839A791DD70E8C",
    },
    Kat {
        plaintext: "20",
        aad: "30",
        ciphertext_and_tag: "962B8016836C75A7D86866588CA245D886",
    },
    Kat {
        plaintext: "2021222324252627",
        aad: "",
        ciphertext_and_tag: "E8C3DEEE246CC5EAE455EF6B33B782A3DD91ED6695373C27",
    },
    Kat {
        plaintext: "202122232425262728292A2B2C2D2E",
        aad: "",
        ciphertext_and_tag: "E8C3DEEE246CC5EAE3E872313897A283AECC1DA0834A52940EC4BFCDDB6404",
    },
    Kat {
        plaintext: "202122232425262728292A2B2C2D2E2F",
        aad: "",
        ciphertext_and_tag: "E8C3DEEE246CC5EAE3E872313897A2BB9EAA915C9DD3245D77048F24D46D27A7",
    },
    Kat {
        plaintext: "202122232425262728292A2B2C2D2E2F30",
        aad: "",
        ciphertext_and_tag: "E8C3DEEE246CC5EAE3E872313897A2BB60301002539D456275DD0B0CEAB3B23844",
    },
    Kat {
        plaintext: "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        aad: "303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F",
        ciphertext_and_tag: "CB34D04660A66DBFBE9C856601F5B8AA51A499B55AC8F7FBEFBC331A613EE9CDFD191750A47F211C0A15ED28173D7CAA",
    },
];

fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0);
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = core::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

fn key_and_nonce() -> (Vec<u8>, Vec<u8>) {
    (decode_hex(KEY), decode_hex(NONCE))
}

fn encrypt(plaintext: &[u8], aad: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (key, nonce) = key_and_nonce();
    let params = BorrowedParams::new(&key, &nonce).unwrap();
    let mut engine = Engine::new();
    engine.init(CipherDirection::Encrypt, &params).unwrap();
    engine.process_aad_bytes(aad).unwrap();

    let mut output = vec![0xA5; engine.get_output_size(plaintext.len())];
    let mut written = engine.process_bytes(plaintext, &mut output).unwrap();
    written += engine.do_final(&mut output[written..]).unwrap();
    output.truncate(written);
    let tag = engine.mac().unwrap().to_vec();
    (output, tag)
}

fn decrypt(ciphertext: &[u8], aad: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (key, nonce) = key_and_nonce();
    let params = BorrowedParams::new(&key, &nonce).unwrap();
    let mut engine = Engine::new();
    engine.init(CipherDirection::Decrypt, &params).unwrap();
    engine.process_aad_bytes(aad).unwrap();

    let mut output = vec![0xA5; engine.get_output_size(ciphertext.len())];
    let mut written = engine.process_bytes(ciphertext, &mut output).unwrap();
    written += engine.do_final(&mut output[written..]).unwrap();
    output.truncate(written);
    let tag = engine.mac().unwrap().to_vec();
    (output, tag)
}

#[test]
fn matches_official_finalized_ascon_aead128_vectors() {
    for kat in KATS {
        let plaintext = decode_hex(kat.plaintext);
        let aad = decode_hex(kat.aad);
        let expected = decode_hex(kat.ciphertext_and_tag);

        let (encrypted, generated_tag) = encrypt(&plaintext, &aad);
        assert_eq!(encrypted, expected);
        assert_eq!(generated_tag, expected[expected.len() - 16..]);

        let (decrypted, verified_tag) = decrypt(&expected, &aad);
        assert_eq!(decrypted, plaintext);
        assert_eq!(verified_tag, expected[expected.len() - 16..]);
    }
}

#[test]
fn chunked_processing_matches_the_official_vector() {
    let kat = KATS.last().unwrap();
    let plaintext = decode_hex(kat.plaintext);
    let aad = decode_hex(kat.aad);
    let expected = decode_hex(kat.ciphertext_and_tag);
    let (key, nonce) = key_and_nonce();

    for split in 0..=plaintext.len() {
        let params = BorrowedParams::new(&key, &nonce).unwrap();
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
        let params = BorrowedParams::new(&key, &nonce).unwrap();
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
fn initial_aad_matches_incremental_aad() {
    let kat = KATS.last().unwrap();
    let plaintext = decode_hex(kat.plaintext);
    let aad = decode_hex(kat.aad);
    let expected = decode_hex(kat.ciphertext_and_tag);
    let (key, nonce) = key_and_nonce();
    let params = BorrowedParams::new_with_aad(&key, &nonce, &aad).unwrap();
    let mut engine = Engine::new();
    engine.init(CipherDirection::Encrypt, &params).unwrap();

    let mut output = vec![0_u8; engine.get_output_size(plaintext.len())];
    let mut written = engine.process_bytes(&plaintext, &mut output).unwrap();
    written += engine.do_final(&mut output[written..]).unwrap();
    assert_eq!(&output[..written], expected);
}

#[test]
fn accepts_an_owned_parameter_implementation() {
    let kat = KATS.last().unwrap();
    let plaintext = decode_hex(kat.plaintext);
    let expected = decode_hex(kat.ciphertext_and_tag);
    let params = OwnedParams {
        key: decode_hex(KEY).try_into().unwrap(),
        nonce: decode_hex(NONCE).try_into().unwrap(),
        initial_aad: decode_hex(kat.aad),
    };
    let mut engine = Engine::new();
    engine.init(CipherDirection::Encrypt, &params).unwrap();

    let mut output = vec![0_u8; engine.get_output_size(plaintext.len())];
    let mut written = engine.process_bytes(&plaintext, &mut output).unwrap();
    written += engine.do_final(&mut output[written..]).unwrap();

    assert_eq!(&output[..written], expected);
}

#[test]
fn rejects_modified_tags_and_short_ciphertexts() {
    let plaintext = decode_hex(KATS[9].plaintext);
    let aad = decode_hex(KATS[9].aad);
    let (mut ciphertext, _) = encrypt(&plaintext, &aad);
    *ciphertext.last_mut().unwrap() ^= 1;

    let (key, nonce) = key_and_nonce();
    let params = BorrowedParams::new(&key, &nonce).unwrap();
    let mut engine = Engine::new();
    engine.init(CipherDirection::Decrypt, &params).unwrap();
    let mut output = vec![0xA5; plaintext.len()];
    let written = engine.process_bytes(&ciphertext, &mut output).unwrap();
    assert_eq!(
        engine.do_final(&mut output[written..]),
        Err(AeadCipherError::AuthenticationFailed)
    );
    assert_eq!(engine.mac(), None);
    assert_eq!(
        engine.do_final(&mut output[written..]),
        Err(AeadCipherError::AlreadyFinalised)
    );

    engine.init(CipherDirection::Decrypt, &params).unwrap();
    assert_eq!(engine.process_bytes(&[0_u8; 15], &mut []), Ok(0));
    assert_eq!(
        engine.do_final(&mut []),
        Err(AeadCipherError::CiphertextTooShort {
            minimum: 16,
            actual: 15,
        })
    );
}

#[test]
fn enforces_state_and_output_buffer_rules_without_consuming_input_on_size_error() {
    let (key, nonce) = key_and_nonce();
    let params = BorrowedParams::new(&key, &nonce).unwrap();
    let mut engine = Engine::new();

    assert_eq!(
        engine.process_bytes(&[], &mut []),
        Err(AeadCipherError::NotInitialised)
    );
    engine.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(engine.mac(), None);
    assert_eq!(engine.get_update_output_size(15), 0);
    assert_eq!(engine.get_update_output_size(16), 16);
    assert_eq!(engine.get_output_size(17), 33);

    assert_eq!(
        engine.process_bytes(&[0_u8; 16], &mut [0_u8; 15]),
        Err(AeadCipherError::OutputBufferTooShort {
            required: 16,
            actual: 15,
        })
    );
    assert_eq!(engine.process_bytes(&[0_u8; 16], &mut [0_u8; 16]), Ok(16));
    assert_eq!(
        engine.process_aad_bytes(&[0]),
        Err(AeadCipherError::AadAfterData)
    );

    let mut tag = [0_u8; 16];
    assert_eq!(engine.do_final(&mut tag), Ok(16));
    assert_eq!(engine.mac(), Some(tag.as_slice()));
    assert_eq!(
        engine.process_bytes(&[], &mut []),
        Err(AeadCipherError::AlreadyFinalised)
    );
}
