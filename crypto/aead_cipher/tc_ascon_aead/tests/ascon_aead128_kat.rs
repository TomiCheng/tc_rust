use tc_ascon_aead::aead128::Engine;
use tc_cipher::{AeadCipher, AeadCipherInit, AeadError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::{InitialAadParams, IvParams, KeyParams};

struct Kat {
    plaintext: &'static str,
    aad: &'static str,
    ciphertext_and_tag: &'static str,
}

const KEY: &str = "000102030405060708090A0B0C0D0E0F";
const NONCE: &str = "101112131415161718191A1B1C1D1E1F";

// Official ascon-c finalized Ascon-AEAD128 KATs covering empty input,
// rate-boundary lengths, and multi-block input.
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

fn hex(input: &str) -> Vec<u8> {
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
    (hex(KEY), hex(NONCE))
}

fn encrypt(plaintext: &[u8], aad: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (key, nonce) = key_and_nonce();
    let params = CustomParams::new(&key, &nonce);
    let mut engine = Engine::new();
    engine.init(CipherDirection::Encrypt, &params).unwrap();
    engine.process_aad_bytes(aad).unwrap();

    let mut output = vec![0xa5; engine.get_output_size(plaintext.len())];
    let mut written = engine.process_bytes(plaintext, &mut output).unwrap();
    written += engine.do_final(&mut output[written..]).unwrap();
    output.truncate(written);
    (output, engine.mac().unwrap().to_vec())
}

fn decrypt(ciphertext: &[u8], aad: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (key, nonce) = key_and_nonce();
    let params = CustomParams::new(&key, &nonce);
    let mut engine = Engine::new();
    engine.init(CipherDirection::Decrypt, &params).unwrap();
    engine.process_aad_bytes(aad).unwrap();

    let mut output = vec![0xa5; engine.get_output_size(ciphertext.len())];
    let mut written = engine.process_bytes(ciphertext, &mut output).unwrap();
    written += engine.do_final(&mut output[written..]).unwrap();
    output.truncate(written);
    (output, engine.mac().unwrap().to_vec())
}

#[test]
fn matches_official_finalized_vectors() {
    for kat in KATS {
        let plaintext = hex(kat.plaintext);
        let aad = hex(kat.aad);
        let expected = hex(kat.ciphertext_and_tag);

        let (encrypted, generated_tag) = encrypt(&plaintext, &aad);
        assert_eq!(encrypted, expected);
        assert_eq!(generated_tag, expected[expected.len() - 16..]);

        let (decrypted, verified_tag) = decrypt(&expected, &aad);
        assert_eq!(decrypted, plaintext);
        assert_eq!(verified_tag, expected[expected.len() - 16..]);
    }
}

#[test]
fn chunked_and_initial_aad_processing_match() {
    let kat = KATS.last().unwrap();
    let plaintext = hex(kat.plaintext);
    let aad = hex(kat.aad);
    let expected = hex(kat.ciphertext_and_tag);
    let (key, nonce) = key_and_nonce();

    for split in 0..=plaintext.len() {
        let params = CustomParams::with_aad(&key, &nonce, &aad);
        let mut engine = Engine::new();
        engine.init(CipherDirection::Encrypt, &params).unwrap();
        let mut output = vec![0; expected.len()];
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
        let params = CustomParams::new(&key, &nonce);
        let mut engine = Engine::new();
        engine.init(CipherDirection::Decrypt, &params).unwrap();
        engine.process_aad_bytes(&aad[..15]).unwrap();
        engine.process_aad_bytes(&aad[15..]).unwrap();
        let mut output = vec![0; plaintext.len()];
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
fn rejects_modified_tags_short_ciphertexts_and_bad_state() {
    let plaintext = hex(KATS[9].plaintext);
    let aad = hex(KATS[9].aad);
    let (mut ciphertext, _) = encrypt(&plaintext, &aad);
    *ciphertext.last_mut().unwrap() ^= 1;
    let (key, nonce) = key_and_nonce();
    let params = CustomParams::new(&key, &nonce);
    let mut engine = Engine::new();
    engine.init(CipherDirection::Decrypt, &params).unwrap();
    let mut output = vec![0xa5; plaintext.len()];
    let written = engine.process_bytes(&ciphertext, &mut output).unwrap();
    assert_eq!(
        engine.do_final(&mut output[written..]),
        Err(AeadError::AuthenticationFailed)
    );
    assert_eq!(engine.mac(), None);
    assert_eq!(
        engine.do_final(&mut output[written..]),
        Err(AeadError::AlreadyFinalised)
    );

    engine.init(CipherDirection::Decrypt, &params).unwrap();
    assert_eq!(engine.process_bytes(&[0; 15], &mut []), Ok(0));
    assert_eq!(
        engine.do_final(&mut []),
        Err(AeadError::CiphertextTooShort {
            minimum: 16,
            actual: 15,
        })
    );
}

struct CustomParams<'a> {
    key: &'a [u8],
    nonce: &'a [u8],
    initial_aad: &'a [u8],
}

impl<'a> CustomParams<'a> {
    fn new(key: &'a [u8], nonce: &'a [u8]) -> Self {
        Self::with_aad(key, nonce, &[])
    }

    fn with_aad(key: &'a [u8], nonce: &'a [u8], initial_aad: &'a [u8]) -> Self {
        Self {
            key,
            nonce,
            initial_aad,
        }
    }
}

impl KeyParams for CustomParams<'_> {
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl IvParams for CustomParams<'_> {
    fn iv(&self) -> &[u8] {
        self.nonce
    }
}

impl InitialAadParams for CustomParams<'_> {
    fn initial_aad(&self) -> &[u8] {
        self.initial_aad
    }
}

#[test]
fn caller_defined_params_names_and_errors_work() {
    let key = [0x11; 16];
    let nonce = [0x22; 16];
    let params = CustomParams::new(&key, &nonce);
    let mut concrete = Engine::new();
    concrete.init(CipherDirection::Encrypt, &params).unwrap();

    let mut name = String::new();
    concrete.write_algo_name(&mut name).unwrap();
    assert_eq!(name, "Ascon-AEAD128");
    let cipher: &mut dyn AeadCipher<Error = AeadError> = &mut concrete;
    assert_eq!(cipher.get_output_size(0), 16);

    let bad_key = [0u8; 15];
    let bad = CustomParams::new(&bad_key, &nonce);
    assert_eq!(
        concrete.init(CipherDirection::Encrypt, &bad),
        Err(InitError::InvalidKeyLength(15))
    );
    let bad_nonce = [0u8; 15];
    let bad = CustomParams::new(&key, &bad_nonce);
    assert!(matches!(
        concrete.init(CipherDirection::Encrypt, &bad),
        Err(InitError::InvalidIvLength(15))
    ));
}
