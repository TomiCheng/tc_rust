use std::sync::LazyLock;

#[allow(unused_imports, reason = "unused when the des feature is off")]
use tc_algo_old::{Algo, AnyKeyParams, AnyParams, CipherDirection, CipherEntry, ErrorKind, SecretKey};

// One instance for the whole file, so that its tables are built once
#[allow(
    dead_code,
    reason = "unused when the features of the tests here are off"
)]
static ALGO: LazyLock<Algo> = LazyLock::new(Algo::new);

#[cfg(feature = "des")]
mod with_des {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn params(iv: Option<&str>) -> AnyParams {
        let key = SecretKey::new(hex("0123456789abcdef"));
        let mut params = AnyParams::new(AnyKeyParams::Secret(key));
        params.op.iv = iv.map(hex);
        params
    }

    fn des_entries() -> impl Iterator<Item = &'static CipherEntry> {
        ALGO.cipher()
            .algorithms()
            .filter(|entry| entry.name().starts_with("DES/"))
    }

    // "Now is the time for all "
    const PLAINTEXT: &str = "4e6f77206973207468652074696d6520666f7220616c6c20";

    #[test]
    fn the_modes_without_padding_give_the_fips_81_vectors() {
        for (name, iv, ciphertext) in [
            (
                "DES/ECB/NOPADDING",
                None,
                "3fa40e8a984d48156a271787ab8883f9893d51ec4b563b53",
            ),
            (
                "DES/CBC/NOPADDING",
                Some("1234567890abcdef"),
                "e5c7cdde872bf27c43e934008c389c0f683788499a7c05f6",
            ),
            (
                "DES/CFB/NOPADDING",
                Some("1234567890abcdef"),
                "f3096249c7f46e51a69e839b1a92f78403467133898ea622",
            ),
            (
                "DES/OFB/NOPADDING",
                Some("1234567890abcdef"),
                "f3096249c7f46e5135f24a242eeb3d3f3d6d5be3255af8c3",
            ),
        ] {
            let params = params(iv);
            let output = ALGO
                .cipher()
                .encrypt(name, &params, &hex(PLAINTEXT))
                .unwrap();
            assert_eq!(output, hex(ciphertext), "{name}");
            assert_eq!(
                ALGO.cipher().decrypt(name, &params, &output).unwrap(),
                hex(PLAINTEXT)
            );
        }
    }

    #[test]
    fn every_combination_decrypts_what_it_encrypts() {
        let message: Vec<u8> = (1..=37).collect();
        for entry in des_entries() {
            let mut parts = entry.name().split('/');
            let (mode, padding) = (parts.nth(1).unwrap(), parts.next().unwrap());
            let mut params = match mode {
                "ECB" => params(None),
                _ => params(Some("1011121314151617")),
            };
            if mode == "EAX" {
                params.op.tag_len = Some(8);
            }
            let message = match (mode, padding) {
                ("ECB" | "CBC", "NOPADDING") => &message[..32],
                _ => &message[..],
            };
            let ciphertext = ALGO
                .cipher()
                .encrypt(entry.name(), &params, message)
                .unwrap();
            let plaintext = ALGO
                .cipher()
                .decrypt(entry.name(), &params, &ciphertext)
                .unwrap();
            assert_eq!(plaintext, message, "{}", entry.name());
        }
    }

    #[test]
    fn the_table_has_eax_but_not_the_aead_modes_for_128_bit_blocks() {
        assert_eq!(des_entries().count(), 5 * 7 + 1);
        assert_eq!(
            ALGO.cipher().get_by_name("DES/EAX").unwrap().entry().name(),
            "DES/EAX/NOPADDING"
        );
        for name in ["DES/CCM", "DES/GCM", "DES/OCB"] {
            let error = ALGO.cipher().get_by_name(name).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::UnknownCipher, "{name}");
        }
    }

    #[test]
    fn every_oiw_oid_finds_the_mode_with_its_default_padding() {
        let mut found = Vec::new();
        for entry in des_entries() {
            for oid in entry.oids() {
                let cipher = ALGO.cipher().get_by_oid(&oid.oid()).unwrap();
                assert_eq!(cipher.entry().name(), entry.name(), "{}", oid.dotted());
                found.push((oid.dotted().to_string(), entry.name().to_string()));
            }
        }
        found.sort();
        assert_eq!(
            found,
            [
                ("1.3.14.3.2.6", "DES/ECB/PKCS7PADDING"),
                ("1.3.14.3.2.7", "DES/CBC/PKCS7PADDING"),
                ("1.3.14.3.2.8", "DES/OFB/NOPADDING"),
                ("1.3.14.3.2.9", "DES/CFB/NOPADDING"),
            ]
            .map(|(oid, name)| (oid.to_string(), name.to_string()))
        );
    }

    #[test]
    fn a_key_of_another_length_than_8_bytes_is_invalid() {
        let key = SecretKey::new(vec![1; 16]);
        let params = AnyParams::new(AnyKeyParams::Secret(key));
        let mut cipher = ALGO.cipher().get_by_name("DES/ECB").unwrap();
        let error = cipher.init(CipherDirection::Encrypt, &params).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}

#[cfg(not(feature = "des"))]
#[test]
fn des_is_an_unknown_cipher_without_its_feature() {
    let error = ALGO.cipher().get_by_name("DES/CBC").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnknownCipher);
}
