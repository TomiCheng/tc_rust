#[cfg(feature = "alloc")]
use tc_aead_cipher::ascon::OwnedParams;
use tc_aead_cipher::{
    AeadCipherError,
    ascon::{BorrowedParams, Engine, KEY_BYTES_80PQ, KEY_BYTES_128, TAG_BYTES, Variant},
};
use tc_cipher_core::{AeadCipher, AeadCipherInit, CipherDirection};

struct Kat {
    plaintext: &'static str,
    aad: &'static str,
    ciphertext_and_tag: &'static str,
}

const KEY_128: &str = "000102030405060708090A0B0C0D0E0F";
const KEY_80PQ: &str = "000102030405060708090A0B0C0D0E0F10111213";
const NONCE: &str = "000102030405060708090A0B0C0D0E0F";

const ASCON128_KATS: &[Kat] = &[
    Kat {
        plaintext: "",
        aad: "",
        ciphertext_and_tag: "E355159F292911F794CB1432A0103A8A",
    },
    Kat {
        plaintext: "",
        aad: "00",
        ciphertext_and_tag: "944DF887CD4901614C5DEDBC42FC0DA0",
    },
    Kat {
        plaintext: "00",
        aad: "",
        ciphertext_and_tag: "BC18C3F4E39ECA7222490D967C79BFFC92",
    },
    Kat {
        plaintext: "0001020304050607",
        aad: "",
        ciphertext_and_tag: "BC820DBDF7A4631C01A8807A44254B42AC6BB490DA1E000A",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F",
        aad: "",
        ciphertext_and_tag: "BC820DBDF7A4631C5B29884AD69175C3F58E28436DD71556D58DFA56AC890BEB",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F",
        aad: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        ciphertext_and_tag: "B96C78651B6246B0C3B1A5D373B0D51656B8B02AE9C620D98ED6E1F8E5589F64",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        aad: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        ciphertext_and_tag: "B96C78651B6246B0C3B1A5D373B0D5168DCA4A96734CF0DDF5F92F8D15E30270279BF6A6CC3F2FC9350B915C292BDB8D",
    },
];

const ASCON128A_KATS: &[Kat] = &[
    Kat {
        plaintext: "",
        aad: "",
        ciphertext_and_tag: "7A834E6F09210957067B10FD831F0078",
    },
    Kat {
        plaintext: "",
        aad: "00",
        ciphertext_and_tag: "AF3031B07B129EC84153373DDCABA528",
    },
    Kat {
        plaintext: "00",
        aad: "",
        ciphertext_and_tag: "6E652B55BFDC8CAD2EC43815B1666B1A3A",
    },
    Kat {
        plaintext: "0001020304050607",
        aad: "",
        ciphertext_and_tag: "6E490CFED5B35467B89C7E12863CE5F76AFC808FFF786B9E",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F",
        aad: "",
        ciphertext_and_tag: "6E490CFED5B3546767350CD83C4ACFBDB10F611B7D79278BD8067FC1BCDF39BE",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F",
        aad: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        ciphertext_and_tag: "A55236AC020DBDA74CE6CCD10C68C4D88A95D7D97F774CB274ACBB055AF1938E",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        aad: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        ciphertext_and_tag: "A55236AC020DBDA74CE6CCD10C68C4D8514450A382BC87C68946D86A921DD88E2ADDDFBBE77D4112830E01960B9D38D5",
    },
];

const ASCON80PQ_KATS: &[Kat] = &[
    Kat {
        plaintext: "",
        aad: "",
        ciphertext_and_tag: "ABB688EFA0B9D56B33277A2C97D2146B",
    },
    Kat {
        plaintext: "",
        aad: "00",
        ciphertext_and_tag: "A259D760E87B0CA73002C3A01E69B567",
    },
    Kat {
        plaintext: "00",
        aad: "",
        ciphertext_and_tag: "28AA80FFF4CA3AF32F60EBCAF63A4CCAB7",
    },
    Kat {
        plaintext: "0001020304050607",
        aad: "",
        ciphertext_and_tag: "2846418067CE93861A484E22565F161146FB6F47913803F9",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F",
        aad: "",
        ciphertext_and_tag: "2846418067CE9386B47F0584BF9EEE3F818CA2B264F3BBFC40B773D0EB81F594",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F",
        aad: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        ciphertext_and_tag: "CC4E07E5FB13426EFFD17B0F51A6A83016F564E1D50A502B9B4FE794A806DC75",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        aad: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        ciphertext_and_tag: "CC4E07E5FB13426EFFD17B0F51A6A830BF484C9651D77679971E8EB4A8EDB5A00782A94C72B2B02D87DCF4AF75DB6996",
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

fn key(variant: Variant) -> Vec<u8> {
    decode_hex(match variant {
        Variant::Ascon128 | Variant::Ascon128a => KEY_128,
        Variant::Ascon80pq => KEY_80PQ,
    })
}

fn kats(variant: Variant) -> &'static [Kat] {
    match variant {
        Variant::Ascon128 => ASCON128_KATS,
        Variant::Ascon128a => ASCON128A_KATS,
        Variant::Ascon80pq => ASCON80PQ_KATS,
    }
}

fn encrypt(variant: Variant, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let key = key(variant);
    let nonce = decode_hex(NONCE);
    let params = BorrowedParams::new(&key, &nonce).unwrap();
    let mut engine = Engine::new(variant);
    engine.init(CipherDirection::Encrypt, &params).unwrap();
    engine.process_aad_bytes(aad).unwrap();

    let mut output = vec![0xA5; engine.get_output_size(plaintext.len())];
    let mut written = engine.process_bytes(plaintext, &mut output).unwrap();
    written += engine.do_final(&mut output[written..]).unwrap();
    output.truncate(written);
    output
}

fn decrypt(variant: Variant, ciphertext: &[u8], aad: &[u8]) -> Vec<u8> {
    let key = key(variant);
    let nonce = decode_hex(NONCE);
    let params = BorrowedParams::new(&key, &nonce).unwrap();
    let mut engine = Engine::new(variant);
    engine.init(CipherDirection::Decrypt, &params).unwrap();
    engine.process_aad_bytes(aad).unwrap();

    let mut output = vec![0xA5; engine.get_output_size(ciphertext.len())];
    let mut written = engine.process_bytes(ciphertext, &mut output).unwrap();
    written += engine.do_final(&mut output[written..]).unwrap();
    output.truncate(written);
    output
}

#[test]
fn matches_legacy_ascon_v12_vectors() {
    for variant in [Variant::Ascon128, Variant::Ascon128a, Variant::Ascon80pq] {
        for kat in kats(variant) {
            let plaintext = decode_hex(kat.plaintext);
            let aad = decode_hex(kat.aad);
            let expected = decode_hex(kat.ciphertext_and_tag);

            assert_eq!(encrypt(variant, &plaintext, &aad), expected);
            assert_eq!(decrypt(variant, &expected, &aad), plaintext);
        }
    }
}

#[test]
fn chunked_processing_matches_vectors() {
    for variant in [Variant::Ascon128, Variant::Ascon128a, Variant::Ascon80pq] {
        let kat = kats(variant).last().unwrap();
        let plaintext = decode_hex(kat.plaintext);
        let aad = decode_hex(kat.aad);
        let expected = decode_hex(kat.ciphertext_and_tag);
        let key = key(variant);
        let nonce = decode_hex(NONCE);

        for split in 0..=plaintext.len() {
            let params = BorrowedParams::new(&key, &nonce).unwrap();
            let mut engine = Engine::new(variant);
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
            let mut engine = Engine::new(variant);
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
}

#[test]
fn initial_aad_matches_incremental_aad() {
    for variant in [Variant::Ascon128, Variant::Ascon128a, Variant::Ascon80pq] {
        let kat = kats(variant).last().unwrap();
        let plaintext = decode_hex(kat.plaintext);
        let aad = decode_hex(kat.aad);
        let expected = decode_hex(kat.ciphertext_and_tag);
        let key = key(variant);
        let nonce = decode_hex(NONCE);
        let params = BorrowedParams::new_with_aad(&key, &nonce, &aad).unwrap();
        let mut engine = Engine::new(variant);
        engine.init(CipherDirection::Encrypt, &params).unwrap();

        let mut output = vec![0_u8; engine.get_output_size(plaintext.len())];
        let mut written = engine.process_bytes(&plaintext, &mut output).unwrap();
        written += engine.do_final(&mut output[written..]).unwrap();
        assert_eq!(&output[..written], expected);
    }
}

#[test]
fn rejects_wrong_variant_key_modified_tags_and_short_ciphertexts() {
    let nonce = decode_hex(NONCE);
    let key_128 = decode_hex(KEY_128);
    let key_80pq = decode_hex(KEY_80PQ);
    let params_128 = BorrowedParams::new(&key_128, &nonce).unwrap();
    let params_80pq = BorrowedParams::new(&key_80pq, &nonce).unwrap();

    let mut engine = Engine::new(Variant::Ascon128);
    assert_eq!(
        engine.init(CipherDirection::Encrypt, &params_80pq),
        Err(AeadCipherError::InvalidKeyLength(KEY_BYTES_80PQ))
    );
    let mut engine = Engine::new(Variant::Ascon80pq);
    assert_eq!(
        engine.init(CipherDirection::Encrypt, &params_128),
        Err(AeadCipherError::InvalidKeyLength(KEY_BYTES_128))
    );

    for variant in [Variant::Ascon128, Variant::Ascon128a, Variant::Ascon80pq] {
        let kat = kats(variant).last().unwrap();
        let plaintext = decode_hex(kat.plaintext);
        let aad = decode_hex(kat.aad);
        let mut ciphertext = encrypt(variant, &plaintext, &aad);
        *ciphertext.last_mut().unwrap() ^= 1;

        let key = key(variant);
        let params = BorrowedParams::new(&key, &nonce).unwrap();
        let mut engine = Engine::new(variant);
        engine.init(CipherDirection::Decrypt, &params).unwrap();
        engine.process_aad_bytes(&aad).unwrap();
        let mut output = vec![0xA5; plaintext.len()];
        let written = engine.process_bytes(&ciphertext, &mut output).unwrap();
        assert_eq!(
            engine.do_final(&mut output[written..]),
            Err(AeadCipherError::AuthenticationFailed)
        );
        assert_eq!(engine.mac(), None);

        engine.init(CipherDirection::Decrypt, &params).unwrap();
        assert_eq!(engine.process_bytes(&[0_u8; TAG_BYTES - 1], &mut []), Ok(0));
        assert_eq!(
            engine.do_final(&mut []),
            Err(AeadCipherError::CiphertextTooShort {
                minimum: TAG_BYTES,
                actual: TAG_BYTES - 1,
            })
        );
    }
}

#[test]
fn reports_variant_metadata_and_enforces_state_rules() {
    let cases = [
        (Variant::Ascon128, "Ascon-128 AEAD", KEY_BYTES_128, 8),
        (Variant::Ascon128a, "Ascon-128a AEAD", KEY_BYTES_128, 16),
        (Variant::Ascon80pq, "Ascon-80pq AEAD", KEY_BYTES_80PQ, 8),
    ];

    for (variant, name, key_bytes, rate) in cases {
        let key = key(variant);
        let nonce = decode_hex(NONCE);
        let params = BorrowedParams::new(&key, &nonce).unwrap();
        let mut engine = Engine::new(variant);

        assert_eq!(engine.variant(), variant);
        assert_eq!(engine.algorithm_name(), name);
        assert_eq!(engine.key_bytes(), key_bytes);
        assert_eq!(engine.nonce_bytes(), 16);
        assert_eq!(engine.tag_bytes(), TAG_BYTES);
        assert_eq!(engine.get_update_output_size(rate), rate);
        assert_eq!(engine.get_output_size(0), TAG_BYTES);
        assert_eq!(
            engine.process_bytes(&[], &mut []),
            Err(AeadCipherError::NotInitialised)
        );

        engine.init(CipherDirection::Encrypt, &params).unwrap();
        let input = [0_u8; 16];
        assert_eq!(engine.get_update_output_size(rate - 1), 0);
        assert_eq!(engine.get_update_output_size(rate), rate);
        assert_eq!(
            engine.process_bytes(&input[..rate], &mut [0_u8; 7]),
            Err(AeadCipherError::OutputBufferTooShort {
                required: rate,
                actual: 7,
            })
        );
        assert_eq!(
            engine.process_bytes(&input[..rate], &mut [0_u8; 16]),
            Ok(rate)
        );
        assert_eq!(
            engine.process_aad_bytes(&[0]),
            Err(AeadCipherError::AadAfterData)
        );

        let mut tag = [0_u8; TAG_BYTES];
        assert_eq!(engine.do_final(&mut tag), Ok(TAG_BYTES));
        assert_eq!(engine.mac(), Some(tag.as_slice()));
        assert_eq!(
            engine.process_bytes(&[], &mut []),
            Err(AeadCipherError::AlreadyFinalised)
        );
    }
}

#[cfg(feature = "alloc")]
#[test]
fn owned_params_match_the_ascon80pq_vector() {
    let variant = Variant::Ascon80pq;
    let kat = kats(variant).last().unwrap();
    let plaintext = decode_hex(kat.plaintext);
    let expected = decode_hex(kat.ciphertext_and_tag);
    let key = key(variant);
    let nonce = decode_hex(NONCE);
    let params = OwnedParams::new_with_aad(&key, &nonce, decode_hex(kat.aad)).unwrap();
    let mut engine = Engine::new(variant);
    engine.init(CipherDirection::Encrypt, &params).unwrap();

    let mut output = vec![0_u8; engine.get_output_size(plaintext.len())];
    let mut written = engine.process_bytes(&plaintext, &mut output).unwrap();
    written += engine.do_final(&mut output[written..]).unwrap();
    assert_eq!(&output[..written], expected);
}
