use tc_aes::AesEngine;
use tc_cipher::{BlockCipher, BlockError, InitError as CipherInitError};
use tc_cmac::{CMac, CreateError, Error, InitError as CmacInitError};
use tc_crypto::AlgorithmName;
use tc_des::DesEdeEngine;
use tc_macs::{Mac, MacInit};
use tc_params::KeyRef;

fn decode(hex: &str) -> Vec<u8> {
    let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty(), "odd-length hexadecimal test vector");

    pairs
        .iter()
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("invalid hexadecimal test vector"),
            };
            (digit(pair[0]) << 4) | digit(pair[1])
        })
        .collect()
}

fn assert_aes_vector(key: &str, message: &str, expected: &str) {
    let key = decode(key);
    let message = decode(message);
    let expected = decode(expected);
    let mut cmac = CMac::new(AesEngine::new()).unwrap();

    cmac.init(&KeyRef::new(&key)).unwrap();
    cmac.update(&message).unwrap();

    let mut actual = [0_u8; 16];
    assert_eq!(cmac.do_final(&mut actual), Ok(16));
    assert_eq!(actual.as_slice(), expected);
}

#[test]
fn matches_nist_and_bouncy_castle_aes_vectors() {
    let messages = [
        "",
        "6bc1bee22e409f96e93d7e117393172a",
        concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411"
        ),
        concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "f69f2445df4f9b17ad2b417be66c3710"
        ),
    ];
    let cases = [
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            [
                "bb1d6929e95937287fa37d129b756746",
                "070a16b46b4d4144f79bdd9dd04a287c",
                "dfa66747de9ae63030ca32611497c827",
                "51f0bebf7e3b9d92fc49741779363cfe",
            ],
        ),
        (
            "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
            [
                "d17ddf46adaacde531cac483de7a9367",
                "9e99a7bf31e710900662f65e617c5184",
                "8a1de5be2eb31aad089a82e6ee908b0e",
                "a1d5df0eed790f794d77589659f39a11",
            ],
        ),
        (
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            [
                "028962f61b7bf89efc6b551f4667d983",
                "28a7023f452e8f82bd4bf28d8c37c35c",
                "aaf3d8f1de5640c232f5b169b9c911e6",
                "e1992190549f6ed5696a2c056c315410",
            ],
        ),
    ];

    for (key, expected) in cases {
        for (message, expected) in messages.into_iter().zip(expected) {
            assert_aes_vector(key, message, expected);
        }
    }
}

#[test]
fn matches_bouncy_castle_des_ede_vector() {
    let key = decode("2b7e151628aed2a6abf7158809cf4f3c");
    let mut cmac = CMac::new(DesEdeEngine::new()).unwrap();
    cmac.init(&KeyRef::new(&key)).unwrap();

    let mut actual = [0_u8; 8];
    assert_eq!(cmac.do_final(&mut actual), Ok(8));
    assert_eq!(actual, [0x1c, 0xa6, 0x70, 0xde, 0xa3, 0x81, 0xd3, 0x7c]);
}

#[test]
fn arbitrary_chunking_keeps_the_last_complete_block() {
    let key = decode("2b7e151628aed2a6abf7158809cf4f3c");
    let message = decode(concat!(
        "6bc1bee22e409f96e93d7e117393172a",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "f69f2445df4f9b17ad2b417be66c3710"
    ));
    let mut cmac = CMac::new(AesEngine::new()).unwrap();
    cmac.init(&KeyRef::new(&key)).unwrap();

    for chunk in message.chunks(3) {
        cmac.update(chunk).unwrap();
    }

    let mut actual = [0_u8; 16];
    cmac.do_final(&mut actual).unwrap();
    assert_eq!(
        actual,
        decode("51f0bebf7e3b9d92fc49741779363cfe").as_slice()
    );
}

#[test]
fn supports_truncated_tags_and_retains_the_key_after_finalization() {
    let key = decode("2b7e151628aed2a6abf7158809cf4f3c");
    let message = decode("6bc1bee22e409f96e93d7e117393172a");
    let mut cmac = CMac::with_mac_size_bits(AesEngine::new(), 64).unwrap();
    cmac.init(&KeyRef::new(&key)).unwrap();

    for _ in 0..2 {
        cmac.update(&message).unwrap();
        let mut actual = [0_u8; 8];
        assert_eq!(cmac.do_final(&mut actual), Ok(8));
        assert_eq!(actual, [0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44]);
    }
}

#[test]
fn reports_lifecycle_and_size_errors() {
    let mut cmac = CMac::new(AesEngine::new()).unwrap();
    assert_eq!(cmac.update(&[]), Err(Error::NotInitialised));

    let key = [0_u8; 16];
    cmac.init(&KeyRef::new(&key)).unwrap();
    cmac.update(b"message").unwrap();
    assert_eq!(
        cmac.do_final(&mut [0_u8; 15]),
        Err(Error::OutputTooShort {
            required: 16,
            available: 15,
        })
    );

    let mut tag = [0_u8; 16];
    assert_eq!(cmac.do_final(&mut tag), Ok(16));

    assert!(matches!(
        CMac::with_mac_size_bits(AesEngine::new(), 0),
        Err(CreateError::InvalidMacSize { .. })
    ));
    assert!(matches!(
        CMac::with_mac_size_bits(AesEngine::new(), 7),
        Err(CreateError::InvalidMacSize { .. })
    ));
    assert!(matches!(
        CMac::with_mac_size_bits(AesEngine::new(), 136),
        Err(CreateError::InvalidMacSize { .. })
    ));

    struct OddBlockCipher;

    impl BlockCipher for OddBlockCipher {
        type Error = BlockError;

        fn block_size(&self) -> usize {
            4
        }

        fn process_block(
            &mut self,
            _input: &[u8],
            _output: &mut [u8],
        ) -> Result<usize, Self::Error> {
            unreachable!()
        }
    }

    assert!(matches!(
        CMac::new(OddBlockCipher),
        Err(CreateError::UnsupportedBlockSize(4))
    ));

    let _type_check: Option<Error<BlockError>> = None;
}

#[test]
fn preserves_the_underlying_cipher_initialization_error() {
    let mut cmac = CMac::new(AesEngine::new()).unwrap();
    assert_eq!(
        cmac.init(&KeyRef::new(&[0_u8; 15])),
        Err(CmacInitError::CipherInit(
            CipherInitError::InvalidKeyLength(15)
        ))
    );
    assert_eq!(cmac.update(&[]), Err(Error::NotInitialised));
}

#[test]
fn composes_the_algorithm_name_and_supports_mac_dispatch() {
    let mut cmac = CMac::new(AesEngine::new()).unwrap();
    let mut name = String::new();
    cmac.write_algo_name(&mut name).unwrap();
    assert_eq!(name, "AES/CMAC");

    cmac.init(&KeyRef::new(&[0_u8; 16])).unwrap();
    let mac: &mut dyn Mac<Error = Error<BlockError>> = &mut cmac;
    mac.update(b"message").unwrap();
    assert_eq!(mac.do_final(&mut [0_u8; 16]), Ok(16));
}
