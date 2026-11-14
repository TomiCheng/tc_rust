#[cfg(feature = "desede")]
use tc_des::DesEdeEngine;
#[cfg(feature = "des")]
use tc_des::DesEngine;

use super::block::{Mode, Padding, Rand, block_cipher, block_rows};
use crate::DefaultAlgoContext;
use crate::cipher::CipherEntry;

// The rows of DES, to give to DefaultAlgoBuilder::reg_cipher: each mode with each padding it takes.
// The OIDs are those of Bouncy Castle's CipherUtilities, where the OIW ones of ECB and CBC mean those
// modes with PKCS#7, and of CFB and OFB those with none
#[cfg(feature = "des")]
pub(super) fn des(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    block_rows(
        &["DES"],
        block_cipher!(DesEngine::new()),
        rand,
        &[
            (Mode::Ecb, Padding::Pkcs7, &["1.3.14.3.2.6"]),
            (Mode::Cbc, Padding::Pkcs7, &["1.3.14.3.2.7"]),
            (Mode::Ofb, Padding::None, &["1.3.14.3.2.8"]),
            (Mode::Cfb, Padding::None, &["1.3.14.3.2.9"]),
        ],
    )
}

// The rows of DESede, three-key or two-key triple DES: each mode with each padding it takes, also
// named TDEA, as in Bouncy Castle's CipherUtilities. Its OIDs are OIW's DESede, which means ECB with
// PKCS#7, and RSA's DES-EDE3-CBC, CBC with PKCS#7
#[cfg(feature = "desede")]
pub(super) fn desede(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    block_rows(
        &["DESEDE", "TDEA"],
        block_cipher!(DesEdeEngine::new()),
        rand,
        &[
            (Mode::Ecb, Padding::Pkcs7, &["1.3.14.3.2.17"]),
            (Mode::Cbc, Padding::Pkcs7, &["1.2.840.113549.3.7"]),
        ],
    )
}

#[cfg(all(test, feature = "des"))]
mod tests {
    use crate::cipher::CipherDirection;
    use crate::params::{KeyOwned, KeyWithIvOwned};
    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind};

    // The examples of FIPS 81, appendix B
    const KEY: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    const IV: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef];
    const PLAINTEXT: &[u8; 24] = b"Now is the time for all ";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn key() -> KeyOwned {
        KeyOwned::new(KEY.to_vec())
    }

    fn key_with_iv() -> KeyWithIvOwned {
        KeyWithIvOwned::new(KEY.to_vec(), IV.to_vec())
    }

    #[test]
    fn the_modes_give_the_examples_of_fips_81() {
        let algo = DefaultAlgoBuilder::default().build();
        let ecb = algo
            .cipher()
            .encrypt_by_name("DES/ECB/NOPADDING", &key(), PLAINTEXT)
            .unwrap();
        assert_eq!(
            hex(&ecb),
            "3fa40e8a984d48156a271787ab8883f9893d51ec4b563b53"
        );
        for (name, expected) in [
            (
                "DES/CBC/NOPADDING",
                "e5c7cdde872bf27c43e934008c389c0f683788499a7c05f6",
            ),
            (
                "DES/CFB/NOPADDING",
                "f3096249c7f46e51a69e839b1a92f78403467133898ea622",
            ),
            (
                "DES/OFB/NOPADDING",
                "f3096249c7f46e5135f24a242eeb3d3f3d6d5be3255af8c3",
            ),
        ] {
            let output = algo
                .cipher()
                .encrypt_by_name(name, &key_with_iv(), PLAINTEXT)
                .unwrap();
            assert_eq!(hex(&output), expected, "{name}");
        }
    }

    #[test]
    fn every_padding_of_ecb_and_cbc_comes_back_whole() {
        let algo = DefaultAlgoBuilder::default().build();
        let message = b"thirteen byte";
        for padding in [
            "PKCS7PADDING",
            "ISO10126PADDING",
            "ISO7816-4PADDING",
            "X923PADDING",
            "TBCPADDING",
            "ZEROBYTEPADDING",
        ] {
            let name = format!("DES/ECB/{padding}");
            let sealed = algo
                .cipher()
                .encrypt_by_name(&name, &key(), message)
                .unwrap();
            assert_eq!(sealed.len(), 16, "{name}");
            let opened = algo
                .cipher()
                .decrypt_by_name(&name, &key(), &sealed)
                .unwrap();
            assert_eq!(opened, message, "{name}");

            let name = format!("DES/CBC/{padding}");
            let params = key_with_iv();
            let sealed = algo
                .cipher()
                .encrypt_by_name(&name, &params, message)
                .unwrap();
            let opened = algo
                .cipher()
                .decrypt_by_name(&name, &params, &sealed)
                .unwrap();
            assert_eq!(opened, message, "{name}");
        }
    }

    #[test]
    fn ctr_takes_any_length_and_comes_back_whole() {
        let algo = DefaultAlgoBuilder::default().build();
        let message = b"not a whole number of blocks";
        for name in ["DES/CTR/NOPADDING", "DES/SIC/NOPADDING"] {
            let sealed = algo
                .cipher()
                .encrypt_by_name(name, &key_with_iv(), message)
                .unwrap();
            assert_eq!(sealed.len(), message.len());
            assert_ne!(&sealed[..], &message[..]);
            let opened = algo
                .cipher()
                .decrypt_by_name(name, &key_with_iv(), &sealed)
                .unwrap();
            assert_eq!(opened, message);
        }
    }

    #[test]
    fn there_are_twenty_one_rows_with_gofb_openpgp_cfb_and_cts_and_the_aliases_and_oids_of_bouncy_castle()
     {
        let algo = DefaultAlgoBuilder::default().build();
        let names: Vec<String> = algo
            .cipher()
            .algorithms()
            .map(|entry| entry.name().to_string())
            .filter(|name| name.starts_with("DES/"))
            .collect();
        assert_eq!(names.len(), 21);

        let cbc = "DES/CBC/PKCS7PADDING";
        for alias in ["des/cbc/pkcs5", "DES/CBC/PKCS7", "DES/CBC/PKCS5PADDING"] {
            let sealed = algo
                .cipher()
                .encrypt_by_name(alias, &key_with_iv(), PLAINTEXT)
                .unwrap();
            let expected = algo
                .cipher()
                .encrypt_by_name(cbc, &key_with_iv(), PLAINTEXT)
                .unwrap();
            assert_eq!(sealed, expected, "{alias}");
        }

        for (oid, name) in [
            ("1.3.14.3.2.6", "DES/ECB/PKCS7PADDING"),
            ("1.3.14.3.2.7", "DES/CBC/PKCS7PADDING"),
            ("1.3.14.3.2.8", "DES/OFB/NOPADDING"),
            ("1.3.14.3.2.9", "DES/CFB/NOPADDING"),
        ] {
            let cipher = algo.cipher().get_by_oid(&oid.parse().unwrap()).unwrap();
            let found = algo.cipher().get_by_name(name).unwrap();
            assert_eq!(cipher.block_size(), found.block_size(), "{oid}");
        }
    }

    #[test]
    fn an_iv_not_of_one_block_or_params_of_another_type_are_invalid_params() {
        let algo = DefaultAlgoBuilder::default().build();
        let mut cbc = algo.cipher().get_by_name("DES/CBC/PKCS7PADDING").unwrap();
        let short = KeyWithIvOwned::new(KEY.to_vec(), vec![0; 7]);
        let error = cbc.init(CipherDirection::Encrypt, &short).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
        let error = cbc.init(CipherDirection::Encrypt, &key()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);

        let mut ecb = algo.cipher().get_by_name("DES/ECB/PKCS7PADDING").unwrap();
        let error = ecb
            .init(CipherDirection::Encrypt, &key_with_iv())
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}

#[cfg(all(test, feature = "desede"))]
mod desede_tests {
    use crate::params::{KeyOwned, KeyWithIvOwned};
    use crate::{AlgoBuilder, DefaultAlgoBuilder};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    // NIST SP 800-67 Rev. 1, appendix B: three keys, ECB
    #[test]
    fn three_key_desede_gives_the_example_of_sp_800_67() {
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
            0xef, 0x01, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23,
        ];
        let algo = DefaultAlgoBuilder::default().build();
        let output = algo
            .cipher()
            .encrypt_by_name(
                "DESEDE/ECB/NOPADDING",
                &KeyOwned::new(key.to_vec()),
                b"The qufck brown fox jump",
            )
            .unwrap();
        assert_eq!(
            hex(&output),
            "a826fd8ce53b855fcce21c8112256fe668d5c05dd9b6b900"
        );
    }

    // With the same key three times, DESede is DES: the example of FIPS 81, appendix B
    #[test]
    fn desede_with_one_key_three_times_is_des() {
        let des_key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let iv = [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef];
        let key = des_key.repeat(3);
        let algo = DefaultAlgoBuilder::default().build();
        let output = algo
            .cipher()
            .encrypt_by_name(
                "DESEDE/CBC/NOPADDING",
                &KeyWithIvOwned::new(key, iv.to_vec()),
                b"Now is the time for all ",
            )
            .unwrap();
        assert_eq!(
            hex(&output),
            "e5c7cdde872bf27c43e934008c389c0f683788499a7c05f6"
        );
    }

    #[test]
    fn desede_has_twenty_one_rows_with_gofb_openpgp_cfb_and_cts_named_desede_or_tdea_with_two_oids()
    {
        let algo = DefaultAlgoBuilder::default().build();
        let names: Vec<String> = algo
            .cipher()
            .algorithms()
            .map(|entry| entry.name().to_string())
            .filter(|name| name.starts_with("DESEDE/"))
            .collect();
        assert_eq!(names.len(), 21);

        // A two-key DESede key, of 16 bytes
        let params = KeyWithIvOwned::new(vec![7; 16], vec![9; 8]);
        let message = b"attack at dawn";
        let expected = algo
            .cipher()
            .encrypt_by_name("DESEDE/CBC/PKCS7PADDING", &params, message)
            .unwrap();
        for alias in [
            "TDEA/CBC/PKCS7PADDING",
            "desede/cbc/pkcs5",
            "TDEA/CBC/PKCS5PADDING",
        ] {
            let output = algo
                .cipher()
                .encrypt_by_name(alias, &params, message)
                .unwrap();
            assert_eq!(output, expected, "{alias}");
        }
        let oid = "1.2.840.113549.3.7".parse().unwrap();
        let output = algo
            .cipher()
            .encrypt_by_oid(&oid, &params, message)
            .unwrap();
        assert_eq!(output, expected);

        let key = KeyOwned::new(vec![7; 24]);
        let expected = algo
            .cipher()
            .encrypt_by_name("DESEDE/ECB/PKCS7PADDING", &key, message)
            .unwrap();
        let oid = "1.3.14.3.2.17".parse().unwrap();
        let output = algo.cipher().encrypt_by_oid(&oid, &key, message).unwrap();
        assert_eq!(output, expected);
    }
}
