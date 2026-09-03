use core::convert::Infallible;

use tc_aes::AesEngine;
use tc_cipher::{BlockCipher, BlockCipherInit, BlockModeInitError, CipherDirection};
use tc_crypto::AlgorithmName;
use tc_gost28147::{Gost28147Engine, s_box};
use tc_ofb::{GCTR_BLOCK_BYTES, GofbBlockCipher};
use tc_params::{IvParams, KeyParams, SBoxParams};

struct Params<'a> {
    key: &'a [u8],
    iv: &'a [u8],
    s_box: &'a [u8],
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

impl SBoxParams for Params<'_> {
    fn s_box(&self) -> &[u8] {
        self.s_box
    }
}

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

const TEST_S_BOX: [u8; 128] = [
    0xE, 0x3, 0xC, 0xD, 0x1, 0xF, 0xA, 0x9, 0xB, 0x6, 0x2, 0x7, 0x5, 0x0, 0x8, 0x4, 0xD, 0x9, 0x0,
    0x4, 0x7, 0x1, 0x3, 0xB, 0x6, 0xC, 0x2, 0xA, 0xF, 0xE, 0x5, 0x8, 0x8, 0xB, 0xA, 0x7, 0x1, 0xD,
    0x5, 0xC, 0x6, 0x3, 0x9, 0x0, 0xF, 0xE, 0x2, 0x4, 0xD, 0x7, 0xC, 0x9, 0xF, 0x0, 0x5, 0x8, 0xA,
    0x2, 0xB, 0x6, 0x4, 0x3, 0x1, 0xE, 0xB, 0x4, 0x6, 0x5, 0x0, 0xF, 0x1, 0xC, 0x9, 0xE, 0xD, 0x8,
    0x3, 0x7, 0xA, 0x2, 0xD, 0xF, 0x9, 0x4, 0x2, 0xC, 0x5, 0xA, 0x6, 0x0, 0x3, 0x8, 0x7, 0xE, 0x1,
    0xB, 0xF, 0xE, 0x9, 0x5, 0xB, 0x2, 0x1, 0x8, 0x6, 0x0, 0xD, 0x3, 0x4, 0x7, 0xC, 0xA, 0xA, 0x3,
    0xE, 0x2, 0x0, 0x1, 0x4, 0x6, 0xB, 0x8, 0xC, 0x7, 0xD, 0x5, 0xF, 0x9,
];

#[test]
fn matches_bouncy_castle_gost_vector() {
    let key = unhex("0011223344556677889900112233445566778899001122334455667788990011");
    let iv = unhex("1234567890abcdef");
    let input = unhex("bc350e71aa113457");
    let mut output = [0; GCTR_BLOCK_BYTES];
    let params = Params {
        key: &key,
        iv: &iv,
        s_box: &s_box::DEFAULT,
    };

    let mut mode = GofbBlockCipher::new(Gost28147Engine::new()).unwrap();
    mode.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(
        mode.process_block(&input, &mut output),
        Ok(GCTR_BLOCK_BYTES)
    );
    assert_eq!(output.as_slice(), unhex("8824c124c4fd1430"));
}

#[test]
fn matches_bouncy_castle_custom_s_box_vectors() {
    let key = unhex("0A43145BA8B9E9FF0AEA67D3F26AD87854CED8D9017B3D33ED81301F90FDF993");

    for (iv, input, expected) in [
        (
            "8001069080010690",
            "094C912C5EFDD703D42118971694580B",
            "2707B58DF039D1A64460735FFE76D55F",
        ),
        (
            "800107A0800107A0",
            "FE780800E0690083F20C010CF00C0329",
            "9AF623DFF948B413B53171E8D546188D",
        ),
    ] {
        let iv = unhex(iv);
        let input = unhex(input);
        let params = Params {
            key: &key,
            iv: &iv,
            s_box: &TEST_S_BOX,
        };
        let mut mode = GofbBlockCipher::new(Gost28147Engine::new()).unwrap();
        mode.init(CipherDirection::Encrypt, &params).unwrap();

        let mut output = vec![0; input.len()];
        for (input, output) in input
            .chunks(GCTR_BLOCK_BYTES)
            .zip(output.chunks_mut(GCTR_BLOCK_BYTES))
        {
            mode.process_block(input, output).unwrap();
        }
        assert_eq!(output, unhex(expected));
    }
}

#[test]
fn reports_name_and_rejects_non_64_bit_ciphers() {
    let mode = GofbBlockCipher::new(Gost28147Engine::new()).unwrap();
    let mut name = String::new();
    mode.write_algo_name(&mut name).unwrap();
    assert_eq!(name, "Gost28147/GCTR");

    assert!(matches!(
        GofbBlockCipher::new(AesEngine::new()),
        Err(BlockModeInitError::<Infallible>::UnsupportedBlockSize {
            actual: 16,
            required: 8,
        })
    ));
}
