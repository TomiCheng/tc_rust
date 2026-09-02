use tc_cipher::{AeadCipher, AeadCipherInit, AeadError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_sparkle_aead::{Engine, Params, Variant};

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

const KEY_128: &str = "000102030405060708090A0B0C0D0E0F";
const KEY_192: &str = "000102030405060708090A0B0C0D0E0F1011121314151617";
const KEY_256: &str = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
const NONCE_128: &str = "000102030405060708090A0B0C0D0E0F";
const NONCE_192: &str = "000102030405060708090A0B0C0D0E0F1011121314151617";
const NONCE_256: &str = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";

const SCHWAEMM128_128_KATS: &[Kat] = &[
    Kat {
        plaintext: "",
        aad: "",
        ciphertext_and_tag: "DDCE77CDB748E6D053CAB7E9190A8349",
    },
    Kat {
        plaintext: "",
        aad: "00",
        ciphertext_and_tag: "D2A4133E82B64F800B6DAB2403FB094D",
    },
    Kat {
        plaintext: "",
        aad: "000102030405060708090A0B0C0D0E0F",
        ciphertext_and_tag: "8B7AEE52D40C7E0EDF9CB56FFAE5D882",
    },
    Kat {
        plaintext: "00",
        aad: "",
        ciphertext_and_tag: "FE2647AA4FB548ACF44067BEC0337B4D25",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F",
        aad: "",
        ciphertext_and_tag: "FEDAD36D1A592AEB931BA52BA4056865F5544DD3488406F6AADF8EDAAE271727",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F",
        aad: "000102030405060708090A0B0C0D0E0F",
        ciphertext_and_tag: "CAD1208F3D3FEC73D1E8825FBDD46C880B9AC7E5250D69200396847219FEBA1F",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        aad: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        ciphertext_and_tag: "9C8A78029D70397B63A4CA18C8248B7A5D5DC1DE714CB01AA58EF58DB020C7F6033BF5CB08FA0F06F8F990D07723823F",
    },
];

const SCHWAEMM256_128_KATS: &[Kat] = &[
    Kat {
        plaintext: "",
        aad: "",
        ciphertext_and_tag: "9E3F9F2E8E26E7D00A9EB92730717A51",
    },
    Kat {
        plaintext: "",
        aad: "00",
        ciphertext_and_tag: "57F83C3E696AE65582DD27FE6FC2F239",
    },
    Kat {
        plaintext: "",
        aad: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        ciphertext_and_tag: "23D8A933C4955C665F6143267BE8E714",
    },
    Kat {
        plaintext: "00",
        aad: "",
        ciphertext_and_tag: "9B6F7DB3323C0B372A4584082E5AB4265C",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        aad: "",
        ciphertext_and_tag: "9BAC759DB8D6D0C50EA19385A3456BA7E061097CCB2683B3F4253C36569A3D15A3A5E0AFDFE60754EB50684FE945AA6A",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        aad: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        ciphertext_and_tag: "8494EB28D98E391B6914564625B243F63DA336497427884D4275A6AA088B8BEEF1CFB0892801FDD208A134182E5D50CE",
    },
];

const SCHWAEMM192_192_KATS: &[Kat] = &[
    Kat {
        plaintext: "",
        aad: "",
        ciphertext_and_tag: "94FABEF076B80FA4CAE902DC5630A2B7B8A72282A560212C",
    },
    Kat {
        plaintext: "",
        aad: "00",
        ciphertext_and_tag: "8939014B970696487EA3642E508A3620B9919155197EB622",
    },
    Kat {
        plaintext: "",
        aad: "000102030405060708090A0B0C0D0E0F1011121314151617",
        ciphertext_and_tag: "4E5A927A1D3E75375ECF9A6DD2EA287487D89725C289D552",
    },
    Kat {
        plaintext: "00",
        aad: "",
        ciphertext_and_tag: "5B3FF82215AAA826BE2456B0741301105FE9FB87A3308C5826",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F1011121314151617",
        aad: "",
        ciphertext_and_tag: "5B64B794B118330EAE30497A35DF53C12C4097F75FADE23C4425CC72069C7015C285E6509CDC2C066E2C9A0AC2C2916C",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F1011121314151617",
        aad: "000102030405060708090A0B0C0D0E0F1011121314151617",
        ciphertext_and_tag: "C89D91A65AC41ACFB5764B4A3DEA34E522A257FB8EF7D5A64E0CF4A6149A640E3F2F429073D4A4B66AA06A76726A3FB4",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        aad: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        ciphertext_and_tag: "73607099477B4F55A907A30675B67C6F62AC293F66638464B3699970FE3D230B68BF4F61CA3312BEE526DF61C3FB78357F089C3BD9BC1470",
    },
];

const SCHWAEMM256_256_KATS: &[Kat] = &[
    Kat {
        plaintext: "",
        aad: "",
        ciphertext_and_tag: "1E41C39049501061A480341DC8551F3CCE171900EB8F90BA5C54B2A7CC2BFDF2",
    },
    Kat {
        plaintext: "",
        aad: "00",
        ciphertext_and_tag: "6AF0F211BC7FF4186EEA03D37025F294036BE6E90970713E5B5A630FFF07DCBE",
    },
    Kat {
        plaintext: "",
        aad: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        ciphertext_and_tag: "138997A2042D05F53300999C9D169C7AD4CD63F80566547C309838FBE1274F90",
    },
    Kat {
        plaintext: "00",
        aad: "",
        ciphertext_and_tag: "BBE3CED9AB9967846E9F39911BEBA2FFC4585C560043E4381E5FDAF8789265D791",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        aad: "",
        ciphertext_and_tag: "BB5918195DC5D4D944594A7B63D6460140BE022EFB65D13C16FB50A48F224B697E6B81DCA1366D43EE20B152AD39CEFCB6103D3EC26A1DC5277B117ADA1ED1BB",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        aad: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        ciphertext_and_tag: "78CE8B6F9375D22F9CB1B86F2D6420EB1E29B6FF72C255BF2C488F7CE5D787A0E61BB809F333ADC75505C5F799A7D50C8C470CB5CEB82864839233AAEE9BC96C",
    },
];

fn decode_hex(input: &str) -> Vec<u8> {
    let (pairs, remainder) = input.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty(), "hex input must have an even length");
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn material(variant: Variant) -> (Vec<u8>, Vec<u8>) {
    let (key, nonce) = match variant {
        Variant::Schwaemm128_128 => (KEY_128, NONCE_128),
        Variant::Schwaemm256_128 => (KEY_128, NONCE_256),
        Variant::Schwaemm192_192 => (KEY_192, NONCE_192),
        Variant::Schwaemm256_256 => (KEY_256, NONCE_256),
    };
    (decode_hex(key), decode_hex(nonce))
}

fn kats(variant: Variant) -> &'static [Kat] {
    match variant {
        Variant::Schwaemm128_128 => SCHWAEMM128_128_KATS,
        Variant::Schwaemm256_128 => SCHWAEMM256_128_KATS,
        Variant::Schwaemm192_192 => SCHWAEMM192_192_KATS,
        Variant::Schwaemm256_256 => SCHWAEMM256_256_KATS,
    }
}

fn encrypt(variant: Variant, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let (key, nonce) = material(variant);
    let params = Params::new(&key, &nonce, &[]);
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
    let (key, nonce) = material(variant);
    let params = Params::new(&key, &nonce, &[]);
    let mut engine = Engine::new(variant);
    engine.init(CipherDirection::Decrypt, &params).unwrap();
    engine.process_aad_bytes(aad).unwrap();

    let mut output = vec![0xA5; engine.get_output_size(ciphertext.len())];
    let mut written = engine.process_bytes(ciphertext, &mut output).unwrap();
    written += engine.do_final(&mut output[written..]).unwrap();
    output.truncate(written);
    output
}

const VARIANTS: [Variant; 4] = [
    Variant::Schwaemm128_128,
    Variant::Schwaemm256_128,
    Variant::Schwaemm192_192,
    Variant::Schwaemm256_256,
];

#[test]
fn matches_official_schwaemm_vectors() {
    for variant in VARIANTS {
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
    for variant in VARIANTS {
        let kat = kats(variant).last().unwrap();
        let plaintext = decode_hex(kat.plaintext);
        let aad = decode_hex(kat.aad);
        let expected = decode_hex(kat.ciphertext_and_tag);
        let (key, nonce) = material(variant);

        for split in 0..=plaintext.len() {
            let params = Params::new(&key, &nonce, &[]);
            let mut engine = Engine::new(variant);
            engine.init(CipherDirection::Encrypt, &params).unwrap();
            let aad_split = aad.len().min(7);
            engine.process_aad_bytes(&aad[..aad_split]).unwrap();
            engine.process_aad_bytes(&aad[aad_split..]).unwrap();

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
            let params = Params::new(&key, &nonce, &[]);
            let mut engine = Engine::new(variant);
            engine.init(CipherDirection::Decrypt, &params).unwrap();
            let aad_split = aad.len().min(15);
            engine.process_aad_bytes(&aad[..aad_split]).unwrap();
            engine.process_aad_bytes(&aad[aad_split..]).unwrap();

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
    for variant in VARIANTS {
        let kat = kats(variant).last().unwrap();
        let plaintext = decode_hex(kat.plaintext);
        let aad = decode_hex(kat.aad);
        let expected = decode_hex(kat.ciphertext_and_tag);
        let (key, nonce) = material(variant);
        let params = Params::new(&key, &nonce, &aad);
        let mut engine = Engine::new(variant);
        engine.init(CipherDirection::Encrypt, &params).unwrap();

        let mut output = vec![0_u8; expected.len()];
        let mut written = engine.process_bytes(&plaintext, &mut output).unwrap();
        written += engine.do_final(&mut output[written..]).unwrap();
        assert_eq!(&output[..written], expected);
    }
}

#[test]
fn rejects_invalid_lengths_modified_tags_and_short_ciphertexts() {
    for variant in VARIANTS {
        let (key, nonce) = material(variant);
        let mut engine = Engine::new(variant);
        let params = Params::new(&key[..key.len() - 1], &nonce, &[]);
        assert_eq!(
            engine.init(CipherDirection::Encrypt, &params),
            Err(InitError::InvalidKeyLength(key.len() - 1))
        );

        let params = Params::new(&key, &nonce[..nonce.len() - 1], &[]);
        assert_eq!(
            engine.init(CipherDirection::Encrypt, &params),
            Err(InitError::InvalidIvLength(nonce.len() - 1))
        );

        let kat = kats(variant).last().unwrap();
        let aad = decode_hex(kat.aad);
        let mut ciphertext = decode_hex(kat.ciphertext_and_tag);
        *ciphertext.last_mut().unwrap() ^= 1;
        let params = Params::new(&key, &nonce, &[]);
        engine.init(CipherDirection::Decrypt, &params).unwrap();
        engine.process_aad_bytes(&aad).unwrap();
        let mut output = vec![0xA5; engine.get_output_size(ciphertext.len())];
        let written = engine.process_bytes(&ciphertext, &mut output).unwrap();
        assert_eq!(
            engine.do_final(&mut output[written..]),
            Err(AeadError::AuthenticationFailed)
        );

        engine.init(CipherDirection::Decrypt, &params).unwrap();
        engine.process_bytes(&[0_u8; 1], &mut []).unwrap();
        assert_eq!(
            engine.do_final(&mut []),
            Err(AeadError::CiphertextTooShort {
                minimum: variant.tag_bytes(),
                actual: 1,
            })
        );
    }
}

#[test]
fn reports_metadata_and_enforces_state_rules() {
    let cases = [
        (Variant::Schwaemm128_128, "SCHWAEMM128-128", 16, 16, 16),
        (Variant::Schwaemm256_128, "SCHWAEMM256-128", 16, 32, 16),
        (Variant::Schwaemm192_192, "SCHWAEMM192-192", 24, 24, 24),
        (Variant::Schwaemm256_256, "SCHWAEMM256-256", 32, 32, 32),
    ];

    for (variant, name, key_bytes, nonce_bytes, tag_bytes) in cases {
        let (key, nonce) = material(variant);
        let params = Params::new(&key, &nonce, &[]);
        let mut engine = Engine::new(variant);
        assert_eq!(engine.variant(), variant);
        assert_eq!(algo_name(&engine), name);
        assert_eq!(engine.key_bytes(), key_bytes);
        assert_eq!(engine.nonce_bytes(), nonce_bytes);
        assert_eq!(engine.tag_bytes(), tag_bytes);
        assert_eq!(
            engine.process_bytes(&[], &mut []),
            Err(AeadError::NotInitialised)
        );

        engine.init(CipherDirection::Encrypt, &params).unwrap();
        assert_eq!(engine.get_update_output_size(nonce_bytes), 0);
        assert_eq!(engine.get_update_output_size(nonce_bytes + 1), nonce_bytes);
        assert_eq!(
            engine.process_bytes(&vec![0_u8; nonce_bytes + 1], &mut []),
            Err(AeadError::OutputTooShort {
                required: nonce_bytes,
                available: 0,
            })
        );
        assert_eq!(
            engine.process_bytes(&vec![0_u8; nonce_bytes], &mut []),
            Ok(0)
        );
        assert_eq!(engine.get_update_output_size(0), 0);
        assert_eq!(engine.process_bytes(&[], &mut []), Ok(0));

        engine.init(CipherDirection::Encrypt, &params).unwrap();
        engine.process_bytes(&[], &mut []).unwrap();
        assert_eq!(engine.process_aad_bytes(&[0]), Err(AeadError::AadAfterData));
        let mut tag = [0_u8; 32];
        assert_eq!(engine.do_final(&mut tag), Ok(tag_bytes));
        assert_eq!(engine.mac(), Some(&tag[..tag_bytes]));
        assert_eq!(
            engine.process_bytes(&[], &mut []),
            Err(AeadError::AlreadyFinalised)
        );
    }
}
