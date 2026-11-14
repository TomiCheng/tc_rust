use tc_aes::AesEngine;

use super::block::{Mode, Padding, Rand, block_cipher, block_rows};
use crate::DefaultAlgoContext;
use crate::cipher::CipherEntry;

// The rows of AES, to give to DefaultAlgoBuilder::reg_cipher: each mode with each padding it takes,
// the AEAD modes among them. Their names and OIDs are those of Bouncy Castle's CipherUtilities,
// where the NIST ECB and CBC OIDs mean those modes with PKCS#7, and the CFB and OFB ones those with
// none
pub(super) fn aes(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    block_rows(
        &["AES"],
        block_cipher!(AesEngine::new()),
        rand,
        &[
            (
                Mode::Ecb,
                Padding::Pkcs7,
                &[
                    "2.16.840.1.101.3.4.1.1",
                    "2.16.840.1.101.3.4.1.21",
                    "2.16.840.1.101.3.4.1.41",
                ],
            ),
            (
                Mode::Cbc,
                Padding::Pkcs7,
                &[
                    "2.16.840.1.101.3.4.1.2",
                    "2.16.840.1.101.3.4.1.22",
                    "2.16.840.1.101.3.4.1.42",
                ],
            ),
            (
                Mode::Cfb,
                Padding::None,
                &[
                    "2.16.840.1.101.3.4.1.4",
                    "2.16.840.1.101.3.4.1.24",
                    "2.16.840.1.101.3.4.1.44",
                ],
            ),
            (
                Mode::Ofb,
                Padding::None,
                &[
                    "2.16.840.1.101.3.4.1.3",
                    "2.16.840.1.101.3.4.1.23",
                    "2.16.840.1.101.3.4.1.43",
                ],
            ),
            (
                Mode::Gcm,
                Padding::None,
                &[
                    "2.16.840.1.101.3.4.1.6",
                    "2.16.840.1.101.3.4.1.26",
                    "2.16.840.1.101.3.4.1.46",
                ],
            ),
            (
                Mode::Ccm,
                Padding::None,
                &[
                    "2.16.840.1.101.3.4.1.7",
                    "2.16.840.1.101.3.4.1.27",
                    "2.16.840.1.101.3.4.1.47",
                ],
            ),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::aes;
    use crate::cipher::{Cipher, CipherDirection, CipherEntry};
    use crate::params::{AeadParamsOwned, KeyOwned, KeyWithIvOwned};
    use crate::{AlgoBuilder, DefaultAlgoBuilder, DefaultAlgoContext, ErrorKind, Params};

    // The example in FIPS 197, appendix C.1
    const KEY: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const PLAINTEXT: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    const CIPHERTEXT: [u8; 16] = [
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5,
        0x5a,
    ];

    // The first block of the example in NIST SP 800-38A, F.2.1
    const CBC_KEY: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    const CBC_IV: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const CBC_PLAINTEXT: [u8; 16] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a,
    ];
    const CBC_CIPHERTEXT: [u8; 16] = [
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19,
        0x7d,
    ];

    // The first two blocks of the examples in NIST SP 800-38A, F.3.13 and F.4.1, with the key and
    // IV above. The two modes agree on the first block only
    const SECOND_PLAINTEXT: [u8; 16] = [
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e,
        0x51,
    ];
    const CFB_CIPHERTEXT: [u8; 32] = [
        0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20, 0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c, 0xfb,
        0x4a, 0xc8, 0xa6, 0x45, 0x37, 0xa0, 0xb3, 0xa9, 0x3f, 0xcd, 0xe3, 0xcd, 0xad, 0x9f, 0x1c,
        0xe5, 0x8b,
    ];
    const OFB_CIPHERTEXT: [u8; 32] = [
        0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20, 0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c, 0xfb,
        0x4a, 0x77, 0x89, 0x50, 0x8d, 0x16, 0x91, 0x8f, 0x03, 0xf5, 0x3c, 0x52, 0xda, 0xc5, 0x4e,
        0xd8, 0x25,
    ];

    fn entry(name: &str) -> Box<dyn CipherEntry> {
        aes(&DefaultAlgoContext::for_tests())
            .into_iter()
            .find(|row| row.name() == name)
            .expect("a row of AES")
    }

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn key_only(key: &[u8]) -> KeyOwned {
        KeyOwned::new(key.to_vec())
    }

    fn key_and_iv(key: &[u8], iv: &[u8]) -> KeyWithIvOwned {
        KeyWithIvOwned::new(key.to_vec(), iv.to_vec())
    }

    fn keyed(direction: CipherDirection) -> Box<dyn Cipher> {
        let mut cipher = entry("AES/ECB/NOPADDING").create();
        cipher.init(direction, &key_only(&KEY)).unwrap();
        cipher
    }

    fn init_error(name: &str, params: &dyn Params) -> ErrorKind {
        let mut cipher = entry(name).create();
        let result = cipher.init(CipherDirection::Encrypt, params);
        result.unwrap_err().kind()
    }

    #[test]
    fn the_ecb_row_takes_bouncy_castle_s_none_and_an_empty_mode_and_has_no_oids() {
        let entry = entry("AES/ECB/NOPADDING");
        assert_eq!(
            entry.aliases(),
            [
                "AES/NONE/NOPADDING".to_string(),
                "AES//NOPADDING".to_string()
            ]
        );
        assert!(entry.oids().is_empty());
    }

    // NIST SP 800-38A, F.3.7: CFB8-AES128, the first 18 bytes
    #[test]
    fn cfb_takes_a_feedback_size_after_its_name_as_bouncy_castle_does() {
        let key = unhex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = unhex("000102030405060708090a0b0c0d0e0f");
        let plaintext = unhex("6bc1bee22e409f96e93d7e117393172aae2d");
        let params = KeyWithIvOwned::new(key, iv);
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();
        for name in ["AES/CFB8/NOPADDING", "aes/cfb8", "AES/CFB8/RAW"] {
            let ciphertext = ciphers.encrypt_by_name(name, &params, &plaintext).unwrap();
            assert_eq!(
                ciphertext,
                unhex("3b79424c9c0dd436bace9e0ed4586a4f32b9"),
                "{name}"
            );
            let recovered = ciphers.decrypt_by_name(name, &params, &ciphertext).unwrap();
            assert_eq!(recovered, plaintext, "{name}");
        }

        // A whole block is the row without a size
        for mode in ["CFB", "OFB"] {
            let whole = ciphers
                .encrypt_by_name(&format!("AES/{mode}/NOPADDING"), &params, &plaintext)
                .unwrap();
            let sized = ciphers
                .encrypt_by_name(&format!("AES/{mode}128/NOPADDING"), &params, &plaintext)
                .unwrap();
            assert_eq!(sized, whole, "{mode}");
        }

        // OFB with 64 bits differs from a whole block, and decrypts back
        let ofb64 = ciphers
            .encrypt_by_name("AES/OFB64/NOPADDING", &params, &plaintext)
            .unwrap();
        assert_ne!(
            ofb64,
            ciphers
                .encrypt_by_name("AES/OFB/NOPADDING", &params, &plaintext)
                .unwrap()
        );
        assert_eq!(
            ciphers
                .decrypt_by_name("AES/OFB64/NOPADDING", &params, &ofb64)
                .unwrap(),
            plaintext
        );
    }

    // The vector tc_block_modes takes from Bouncy Castle's OpenPgpCfbBlockCipher, with the IV of
    // zeros OpenPGP uses
    #[test]
    fn openpgp_cfb_gives_bouncy_castle_s_vector_with_an_iv_of_zeros() {
        let params = KeyWithIvOwned::new(unhex("000102030405060708090a0b0c0d0e0f"), vec![0; 16]);
        let plaintext: Vec<u8> = (0..64).collect();
        let expected = unhex(concat!(
            "c6a03934838a5d8567468b69adc5d676",
            "a59b6214586273366f14c5ba4fd7b4f3",
            "aac96e3ece517e590c11d41154ca3f74",
            "46c67e57a75188a9a1b186e0e57590db",
        ));
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();
        for name in ["AES/OPENPGPCFB/NOPADDING", "aes/openpgpcfb"] {
            let ciphertext = ciphers.encrypt_by_name(name, &params, &plaintext).unwrap();
            assert_eq!(ciphertext, expected, "{name}");
            let recovered = ciphers.decrypt_by_name(name, &params, &ciphertext).unwrap();
            assert_eq!(recovered, plaintext, "{name}");
        }
        // It is not plain CFB
        let cfb = ciphers
            .encrypt_by_name("AES/CFB/NOPADDING", &params, &plaintext)
            .unwrap();
        assert_ne!(cfb, expected);
    }

    // RFC 3962, appendix B: AES in CBC with ciphertext stealing and an IV of zeros, through each name
    // of the row; and the ECB result Bouncy Castle gives, as tc_cts_modes tests it
    #[test]
    fn cts_gives_the_vectors_of_rfc_3962_and_a_ciphertext_of_the_message_s_length() {
        let key = unhex("636869636b656e207465726979616b69");
        let message = unhex(concat!(
            "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c2070",
            "6c656173652c20616e64207769746820626f74746f6d6c657373",
        ));
        let params = KeyWithIvOwned::new(key.clone(), vec![0; 16]);
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();
        for (len, expected) in [
            (17, "c6353568f2bf8cb4d8a580362da7ff7f97"),
            (
                31,
                "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5",
            ),
            (
                64,
                concat!(
                    "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a8",
                    "426cff30b100ed348cf882311b3266069dad8bbb96c4cdc03bc103e1a194bbd8",
                ),
            ),
        ] {
            for name in ["AES/CBC/WITHCTS", "AES/CTS/NOPADDING", "aes/cts"] {
                let ciphertext = ciphers
                    .encrypt_by_name(name, &params, &message[..len])
                    .unwrap();
                assert_eq!(ciphertext, unhex(expected), "{name} {len}");
                let recovered = ciphers.decrypt_by_name(name, &params, &ciphertext).unwrap();
                assert_eq!(recovered, &message[..len], "{name} {len}");
            }
        }

        let ecb = ciphers
            .encrypt_by_name("AES/ECB/WITHCTS", &KeyOwned::new(key), &message[..47])
            .unwrap();
        assert_eq!(
            ecb,
            unhex(concat!(
                "97687268d6ecccc0c07b25e25ecfe5842f0f4df59a97fd3fb99cbd0c0786a184",
                "230c15eacecdc08fc1e2b658760fff",
            ))
        );
    }

    #[test]
    fn cts_refuses_a_message_shorter_than_a_block() {
        let params = KeyWithIvOwned::new(vec![0x42; 16], vec![0; 16]);
        let algo = DefaultAlgoBuilder::default().build();
        let error = algo
            .cipher()
            .encrypt_by_name("AES/CBC/WITHCTS", &params, &[0; 15])
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DataLength);
    }

    // A standard example of each AEAD mode: SP 800-38C, example 1, for CCM; the EAX paper's first
    // test vector; RFC 7253's first sample for OCB. Each sealed message ends with its tag
    #[test]
    fn ccm_eax_and_ocb_give_their_standard_examples() {
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();
        for (name, key, nonce, tag, aad, plaintext, sealed) in [
            (
                "AES/CCM/NOPADDING",
                "404142434445464748494a4b4c4d4e4f",
                "10111213141516",
                4,
                "0001020304050607",
                "20212223",
                "7162015b4dac255d",
            ),
            (
                "AES/EAX/NOPADDING",
                "233952dee4d5ed5f9b9c6d6ff80ff478",
                "62ec67f9c3a4a407fcb2a8c49031a8b3",
                16,
                "6bfb914fd07eae6b",
                "",
                "e037830e8389f27b025a2d6527e79d01",
            ),
            (
                "AES/OCB/NOPADDING",
                "000102030405060708090a0b0c0d0e0f",
                "bbaa99887766554433221100",
                16,
                "",
                "",
                "785407bfffc8ad9edcc5520ac9111ee6",
            ),
        ] {
            let params = AeadParamsOwned::new(unhex(key), unhex(nonce), tag, unhex(aad));
            let output = ciphers
                .encrypt_by_name(name, &params, &unhex(plaintext))
                .unwrap();
            assert_eq!(output, unhex(sealed), "{name}");
            let opened = ciphers.decrypt_by_name(name, &params, &output).unwrap();
            assert_eq!(opened, unhex(plaintext), "{name}");
        }
    }

    // The AEAD modes take the names that leave the padding out or empty, but not RAW, as Bouncy
    // Castle refuses any padding but NOPADDING for them; GCM, CCM and OCB want a block of 16 bytes
    #[test]
    fn the_aead_modes_reach_every_engine_of_their_block_size() {
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();
        let found = |name: &str| ciphers.get_by_name(name).is_ok();
        assert!(found("AES/GCM") && found("AES/GCM/") && found("aes/ocb/nopadding"));
        assert!(!found("AES/GCM/RAW") && !found("AES/GCM/PKCS7PADDING"));
        #[cfg(feature = "des")]
        {
            assert!(found("DES/EAX/NOPADDING"));
            for mode in ["GCM", "CCM", "OCB"] {
                assert!(!found(&format!("DES/{mode}/NOPADDING")), "{mode}");
            }
        }
        #[cfg(feature = "camellia")]
        {
            let params = AeadParamsOwned::new(vec![0x42; 16], vec![0x24; 12], 16, b"aad".to_vec());
            for mode in ["GCM", "CCM", "EAX", "OCB"] {
                let name = format!("CAMELLIA/{mode}/NOPADDING");
                let sealed = ciphers.encrypt_by_name(&name, &params, b"message").unwrap();
                assert_eq!(sealed.len(), 7 + 16, "{name}");
                let opened = ciphers.decrypt_by_name(&name, &params, &sealed).unwrap();
                assert_eq!(opened, b"message", "{name}");
            }
        }
    }

    #[test]
    fn a_feedback_size_out_of_range_or_on_another_mode_names_no_row() {
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();
        for name in [
            "AES/CFB0/NOPADDING",
            "AES/CFB12/NOPADDING",
            "AES/CFB136/NOPADDING",
            "AES/OFB256/NOPADDING",
            "AES/CBC8/PKCS7PADDING",
            "AES/CTR8/NOPADDING",
            "AES/CFB8/PKCS7PADDING",
            "AES/CFB+8/NOPADDING",
        ] {
            let error = ciphers.get_by_name(name).err().unwrap();
            assert_eq!(error.kind(), ErrorKind::UnknownCipher, "{name}");
        }
        // The rows are listed once, whatever their feedback size
        let cfb = ciphers
            .algorithms()
            .filter(|entry| entry.name().starts_with("AES/CFB"))
            .count();
        assert_eq!(cfb, 1);
    }

    // As Bouncy Castle's CipherUtilities: an empty or missing mode is ECB, and an empty, missing
    // or RAW padding is PKCS#7 in ECB and CBC and none in the other modes
    #[test]
    fn a_name_that_leaves_out_the_mode_or_the_padding_finds_bouncy_castle_s_default() {
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();
        let name_of = |name: &str| ciphers.get_by_name(name).map(|_| ()).is_ok();
        let row_of = |name: &str| {
            ciphers
                .algorithms()
                .find(|entry| {
                    entry.name().eq_ignore_ascii_case(name)
                        || entry
                            .aliases()
                            .iter()
                            .any(|alias| alias.eq_ignore_ascii_case(name))
                })
                .map(|entry| entry.name().to_string())
        };
        for (name, row) in [
            ("AES", "AES/ECB/PKCS7PADDING"),
            ("aes/", "AES/ECB/PKCS7PADDING"),
            ("AES//", "AES/ECB/PKCS7PADDING"),
            ("AES//PKCS7", "AES/ECB/PKCS7PADDING"),
            ("AES//PKCS5PADDING", "AES/ECB/PKCS7PADDING"),
            ("AES/ECB", "AES/ECB/PKCS7PADDING"),
            ("AES/NONE/RAW", "AES/ECB/PKCS7PADDING"),
            ("AES/CBC", "AES/CBC/PKCS7PADDING"),
            ("AES/CBC/", "AES/CBC/PKCS7PADDING"),
            ("AES/CBC/RAW", "AES/CBC/PKCS7PADDING"),
            ("AES/CFB", "AES/CFB/NOPADDING"),
            ("AES/OFB/RAW", "AES/OFB/NOPADDING"),
            ("AES/SIC", "AES/CTR/NOPADDING"),
            ("AES/CBC/X9.23PADDING", "AES/CBC/X923PADDING"),
            ("AES//NOPADDING", "AES/ECB/NOPADDING"),
        ] {
            assert!(name_of(name), "{name}");
            assert_eq!(row_of(name).as_deref(), Some(row), "{name}");
        }
        // A padding left out is not NOPADDING in the modes of whole blocks
        assert_ne!(row_of("AES/CBC").as_deref(), Some("AES/CBC/NOPADDING"));
    }

    #[test]
    fn the_cbc_row_gives_the_standard_ciphertext_through_the_helpers() {
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();
        let params = key_and_iv(&CBC_KEY, &CBC_IV);

        let encrypted = ciphers
            .encrypt_by_name("AES/CBC/NOPADDING", &params, &CBC_PLAINTEXT)
            .unwrap();
        assert_eq!(encrypted, CBC_CIPHERTEXT);

        let decrypted = ciphers
            .decrypt_by_name("AES/CBC/NOPADDING", &params, &CBC_CIPHERTEXT)
            .unwrap();
        assert_eq!(decrypted, CBC_PLAINTEXT);
    }

    #[test]
    fn the_cfb_and_ofb_rows_give_the_standard_ciphertext() {
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();
        let params = key_and_iv(&CBC_KEY, &CBC_IV);
        let plaintext = [CBC_PLAINTEXT, SECOND_PLAINTEXT].concat();

        for (name, ciphertext) in [
            ("AES/CFB/NOPADDING", CFB_CIPHERTEXT),
            ("AES/OFB/NOPADDING", OFB_CIPHERTEXT),
        ] {
            let encrypted = ciphers.encrypt_by_name(name, &params, &plaintext).unwrap();
            assert_eq!(encrypted, ciphertext);

            let decrypted = ciphers.decrypt_by_name(name, &params, &ciphertext).unwrap();
            assert_eq!(decrypted, plaintext);
        }
    }

    #[test]
    fn the_cfb_and_ofb_rows_take_a_partial_last_block() {
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();
        let params = key_and_iv(&CBC_KEY, &CBC_IV);
        let plaintext = [CBC_PLAINTEXT, SECOND_PLAINTEXT].concat();

        for (name, ciphertext) in [
            ("AES/CFB/NOPADDING", CFB_CIPHERTEXT),
            ("AES/OFB/NOPADDING", OFB_CIPHERTEXT),
        ] {
            let encrypted = ciphers
                .encrypt_by_name(name, &params, &plaintext[..20])
                .unwrap();
            assert_eq!(encrypted, ciphertext[..20]);
        }
    }

    #[test]
    fn finalize_goes_back_to_the_iv_as_in_bouncy_castle() {
        let params = key_and_iv(&CBC_KEY, &CBC_IV);

        for name in [
            "AES/CBC/NOPADDING",
            "AES/CFB/NOPADDING",
            "AES/OFB/NOPADDING",
        ] {
            let mut cipher = entry(name).create();
            cipher.init(CipherDirection::Encrypt, &params).unwrap();
            let first = cipher.update(&CBC_PLAINTEXT).unwrap();
            cipher.finalize().unwrap();
            assert_eq!(cipher.update(&CBC_PLAINTEXT).unwrap(), first);
        }
    }

    #[test]
    fn the_padded_rows_take_back_what_they_encrypted() {
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();
        let message = b"attack at dawn";

        let without_iv = key_only(&KEY);
        let with_iv = key_and_iv(&KEY, &CBC_IV);
        let rows: [(&str, &dyn Params); 2] = [
            ("AES/ECB/PKCS7PADDING", &without_iv),
            ("AES/CBC/PKCS7PADDING", &with_iv),
        ];

        for (name, params) in rows {
            let encrypted = ciphers.encrypt_by_name(name, params, message).unwrap();
            assert_eq!(encrypted.len(), 16);
            let decrypted = ciphers.decrypt_by_name(name, params, &encrypted).unwrap();
            assert_eq!(decrypted, message);
        }
    }

    #[test]
    fn a_padded_row_reports_a_bad_padding_as_invalid_ciphertext() {
        let algo = DefaultAlgoBuilder::default().build();
        let params = key_only(&KEY);

        // PLAINTEXT ends in 0xff, which is no PKCS#7 padding
        let result = algo
            .cipher()
            .decrypt_by_name("AES/ECB/PKCS7PADDING", &params, &CIPHERTEXT);
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidCiphertext);
    }

    #[test]
    fn the_ecb_rows_refuse_params_with_an_iv() {
        let params = key_and_iv(&KEY, &CBC_IV);
        for name in ["AES/ECB/NOPADDING", "AES/ECB/PKCS7PADDING"] {
            assert_eq!(init_error(name, &params), ErrorKind::InvalidParams);
        }
    }

    // With an IV of zeros, the first block of CBC is the same as ECB
    #[test]
    fn an_iv_of_zeros_works_when_it_is_given() {
        let algo = DefaultAlgoBuilder::default().build();
        let params = key_and_iv(&KEY, &[0; 16]);

        let encrypted = algo
            .cipher()
            .encrypt_by_name("AES/CBC/NOPADDING", &params, &PLAINTEXT)
            .unwrap();
        assert_eq!(encrypted, CIPHERTEXT);
    }

    #[test]
    fn the_modes_with_an_iv_refuse_a_missing_or_a_wrong_one() {
        let missing = key_only(&KEY);
        let short = key_and_iv(&KEY, &[0; 15]);
        let empty = key_and_iv(&KEY, &[]);
        let long = key_and_iv(&KEY, &[0; 17]);

        for name in [
            "AES/CBC/NOPADDING",
            "AES/CBC/PKCS7PADDING",
            "AES/CFB/NOPADDING",
            "AES/OFB/NOPADDING",
        ] {
            let params: [&dyn Params; 4] = [&missing, &short, &empty, &long];
            for params in params {
                assert_eq!(init_error(name, params), ErrorKind::InvalidParams);
            }
        }
    }

    #[test]
    fn init_refuses_a_key_or_an_iv_of_the_wrong_length() {
        assert_eq!(
            init_error("AES/ECB/NOPADDING", &key_only(&KEY[..15])),
            ErrorKind::InvalidParams
        );
        assert_eq!(
            init_error("AES/CBC/NOPADDING", &key_and_iv(&KEY[..15], &CBC_IV)),
            ErrorKind::InvalidParams
        );
    }

    struct OtherParams;

    impl Params for OtherParams {
        fn as_any(&self) -> &dyn core::any::Any {
            self
        }
    }

    #[test]
    fn init_refuses_params_of_another_type() {
        assert_eq!(
            init_error("AES/ECB/NOPADDING", &OtherParams),
            ErrorKind::InvalidParams
        );
    }

    #[test]
    fn a_new_builder_finds_the_row_by_its_name_whatever_the_case() {
        let algo = DefaultAlgoBuilder::default().build();
        assert!(algo.cipher().get_by_name("AES/ECB/NoPadding").is_ok());
        assert!(algo.cipher().get_by_name("aes/ecb/nopadding").is_ok());
    }

    #[test]
    fn update_holds_a_partial_block_and_gives_the_standard_ciphertext_once_it_is_complete() {
        let mut cipher = keyed(CipherDirection::Encrypt);
        assert!(cipher.update(&PLAINTEXT[..5]).unwrap().is_empty());
        assert_eq!(cipher.update(&PLAINTEXT[5..]).unwrap(), CIPHERTEXT);
        assert!(cipher.finalize().unwrap().is_empty());
    }

    #[test]
    fn decrypting_the_standard_ciphertext_gives_the_plaintext() {
        let mut cipher = keyed(CipherDirection::Decrypt);
        assert_eq!(cipher.update(&CIPHERTEXT).unwrap(), PLAINTEXT);
        assert!(cipher.finalize().unwrap().is_empty());
    }

    #[test]
    fn finalize_reports_a_partial_last_block() {
        let mut cipher = keyed(CipherDirection::Encrypt);
        cipher.update(&PLAINTEXT[..5]).unwrap();
        let error = cipher.finalize().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DataLength);
    }

    #[test]
    fn update_and_finalize_report_a_cipher_that_was_not_initialized() {
        let mut cipher = entry("AES/ECB/NOPADDING").create();
        let error = cipher.update(&PLAINTEXT).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
        let error = cipher.finalize().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
    }

    const GCM: &str = "AES/GCM/NOPADDING";

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    // Test Case 4 of the GCM specification
    fn gcm_params() -> AeadParamsOwned {
        AeadParamsOwned::new(
            hex("feffe9928665731c6d6a8f9467308308"),
            hex("cafebabefacedbaddecaf888"),
            16,
            hex("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
        )
    }

    fn gcm_plaintext() -> Vec<u8> {
        hex(concat!(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        ))
    }

    fn gcm_sealed() -> Vec<u8> {
        hex(concat!(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e",
            "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
            "5bc94fbc3221a5db94fae95ae7121a47",
        ))
    }

    #[test]
    fn the_gcm_row_gives_the_standard_ciphertext_and_tag_through_the_helpers() {
        let algo = DefaultAlgoBuilder::default().build();
        let sealed = algo
            .cipher()
            .encrypt_by_name(GCM, &gcm_params(), &gcm_plaintext())
            .unwrap();
        assert_eq!(sealed, gcm_sealed());
        let opened = algo
            .cipher()
            .decrypt_by_name(GCM, &gcm_params(), &sealed)
            .unwrap();
        assert_eq!(opened, gcm_plaintext());
    }

    #[test]
    fn the_gcm_helpers_report_a_changed_ciphertext_or_a_changed_aad_as_invalid_ciphertext() {
        let algo = DefaultAlgoBuilder::default().build();
        let mut changed = gcm_sealed();
        changed[0] ^= 1;
        let error = algo
            .cipher()
            .decrypt_by_name(GCM, &gcm_params(), &changed)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidCiphertext);

        let other_aad = AeadParamsOwned::new(
            hex("feffe9928665731c6d6a8f9467308308"),
            hex("cafebabefacedbaddecaf888"),
            16,
            vec![],
        );
        let error = algo
            .cipher()
            .decrypt_by_name(GCM, &other_aad, &gcm_sealed())
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidCiphertext);
    }

    #[test]
    fn the_gcm_row_reports_a_ciphertext_shorter_than_the_tag_as_invalid_ciphertext() {
        let algo = DefaultAlgoBuilder::default().build();
        let error = algo
            .cipher()
            .decrypt_by_name(GCM, &gcm_params(), &[0; 15])
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidCiphertext);
    }

    #[test]
    fn the_gcm_row_refuses_params_of_another_type_or_a_key_of_the_wrong_length() {
        assert_eq!(
            init_error(GCM, &key_and_iv(&KEY, &CBC_IV)),
            ErrorKind::InvalidParams
        );
        let short_key = AeadParamsOwned::new(KEY[..15].to_vec(), vec![0; 12], 16, vec![]);
        assert_eq!(init_error(GCM, &short_key), ErrorKind::InvalidParams);
    }

    #[test]
    fn the_gcm_row_reports_a_cipher_that_was_not_initialized() {
        let mut cipher = entry(GCM).create();
        let error = cipher.update(&PLAINTEXT).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
        let error = cipher.finalize().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
    }

    #[test]
    fn the_block_size_is_that_of_aes_in_every_row() {
        for row in aes(&DefaultAlgoContext::for_tests()) {
            assert_eq!(row.create().block_size(), 16, "{}", row.name());
        }
    }

    #[test]
    fn the_buffer_calls_give_the_same_output_as_update_and_finalize() {
        let params = key_and_iv(&CBC_KEY, &CBC_IV);
        let name = "AES/CBC/PKCS7PADDING";
        let expected = DefaultAlgoBuilder::default()
            .build()
            .cipher()
            .encrypt_by_name(name, &params, &CBC_PLAINTEXT)
            .unwrap();

        let mut cipher = entry(name).create();
        cipher.init(CipherDirection::Encrypt, &params).unwrap();
        let mut output = vec![0; cipher.output_len(CBC_PLAINTEXT.len()).unwrap()];
        let mut written = cipher.process_bytes(&CBC_PLAINTEXT, &mut output).unwrap();
        written += cipher.do_final(&mut output[written..]).unwrap();
        assert_eq!(output[..written], expected);
    }

    #[test]
    fn process_byte_gives_the_same_output_as_process_bytes() {
        let mut cipher = keyed(CipherDirection::Encrypt);
        let mut output = [0; 16];
        let mut written = 0;
        for byte in PLAINTEXT {
            written += cipher.process_byte(byte, &mut output[written..]).unwrap();
        }
        assert_eq!(written, 16);
        assert_eq!(output, CIPHERTEXT);
    }

    #[test]
    fn an_output_too_short_is_reported_as_data_length() {
        let mut cipher = keyed(CipherDirection::Encrypt);
        let error = cipher.process_bytes(&PLAINTEXT, &mut [0; 8]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DataLength);

        let mut cipher = entry(GCM).create();
        cipher
            .init(CipherDirection::Encrypt, &gcm_params())
            .unwrap();
        let error = cipher.do_final(&mut [0; 8]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DataLength);
    }

    #[test]
    fn reset_discards_the_message_so_far() {
        let mut cipher = keyed(CipherDirection::Encrypt);
        assert!(cipher.update(&PLAINTEXT[..5]).unwrap().is_empty());
        cipher.reset();
        assert_eq!(cipher.update(&PLAINTEXT).unwrap(), CIPHERTEXT);
    }

    #[test]
    fn reset_starts_a_gcm_decryption_over() {
        let mut cipher = entry(GCM).create();
        cipher
            .init(CipherDirection::Decrypt, &gcm_params())
            .unwrap();
        cipher.update(&gcm_sealed()[..20]).unwrap();
        cipher.reset();
        let mut opened = cipher.update(&gcm_sealed()).unwrap();
        opened.extend(cipher.finalize().unwrap());
        assert_eq!(opened, gcm_plaintext());
    }

    #[test]
    fn reset_does_not_let_a_gcm_encryption_reuse_its_nonce() {
        let mut cipher = entry(GCM).create();
        cipher
            .init(CipherDirection::Encrypt, &gcm_params())
            .unwrap();
        cipher.update(&gcm_plaintext()).unwrap();
        cipher.reset();
        let error = cipher.update(&gcm_plaintext()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
    }

    #[test]
    fn a_finished_gcm_encryption_refuses_more_data_and_the_same_nonce() {
        let mut cipher = entry(GCM).create();
        cipher
            .init(CipherDirection::Encrypt, &gcm_params())
            .unwrap();
        cipher.finalize().unwrap();
        let error = cipher.update(&PLAINTEXT).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
        let error = cipher
            .init(CipherDirection::Encrypt, &gcm_params())
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }

    // NIST SP 800-38A, F.5.1: CTR-AES128, the first block
    #[test]
    fn the_ctr_row_gives_the_example_of_sp_800_38a() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let counter: Vec<u8> = (0xf0..=0xff).collect();
        let plaintext = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let expected = [
            0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d,
            0xb6, 0xce,
        ];
        let algo = DefaultAlgoBuilder::default().build();
        let params = KeyWithIvOwned::new(key.to_vec(), counter);
        for name in ["AES/CTR/NOPADDING", "AES/SIC/NOPADDING"] {
            let output = algo
                .cipher()
                .encrypt_by_name(name, &params, &plaintext)
                .unwrap();
            assert_eq!(output, expected, "{name}");
        }
    }

    #[test]
    fn aes_has_a_row_for_each_mode_with_each_padding_it_takes_and_the_aead_modes() {
        let algo = DefaultAlgoBuilder::default().build();
        let names: Vec<String> = algo
            .cipher()
            .algorithms()
            .map(|entry| entry.name().to_string())
            .filter(|name| name.starts_with("AES/"))
            .collect();
        assert_eq!(names.len(), 24);
        for name in [
            "AES/ECB/X923PADDING",
            "AES/CBC/ISO7816-4PADDING",
            "AES/CBC/ZEROBYTEPADDING",
            "AES/CTR/NOPADDING",
            "AES/GCM/NOPADDING",
        ] {
            assert!(names.iter().any(|found| found == name), "{name}");
        }
    }
}
