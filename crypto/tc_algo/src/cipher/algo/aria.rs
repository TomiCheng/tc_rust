use tc_aria::AriaEngine;

use super::block::{Mode, Padding, Rand, block_cipher, block_rows};
use crate::DefaultAlgoContext;
use crate::cipher::CipherEntry;

// The rows of ARIA, of RFC 5794. Its OIDs are NSRI's, for each mode with 128-, 192- and 256-bit keys, as in Bouncy Castle's CipherUtilities: each mode with each padding it
// takes
pub(super) fn aria(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    block_rows(
        &["ARIA"],
        block_cipher!(AriaEngine::new()),
        rand,
        &[
            (
                Mode::Ecb,
                Padding::Pkcs7,
                &[
                    "1.2.410.200046.1.1.1",
                    "1.2.410.200046.1.1.6",
                    "1.2.410.200046.1.1.11",
                ],
            ),
            (
                Mode::Cbc,
                Padding::Pkcs7,
                &[
                    "1.2.410.200046.1.1.2",
                    "1.2.410.200046.1.1.7",
                    "1.2.410.200046.1.1.12",
                ],
            ),
            (
                Mode::Cfb,
                Padding::None,
                &[
                    "1.2.410.200046.1.1.3",
                    "1.2.410.200046.1.1.8",
                    "1.2.410.200046.1.1.13",
                ],
            ),
            (
                Mode::Ofb,
                Padding::None,
                &[
                    "1.2.410.200046.1.1.4",
                    "1.2.410.200046.1.1.9",
                    "1.2.410.200046.1.1.14",
                ],
            ),
            (
                Mode::Ctr,
                Padding::None,
                &[
                    "1.2.410.200046.1.1.5",
                    "1.2.410.200046.1.1.10",
                    "1.2.410.200046.1.1.15",
                ],
            ),
        ],
    )
}

#[cfg(test)]
mod tests {
    use crate::params::KeyOwned;
    use crate::{AlgoBuilder, DefaultAlgoBuilder};

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    // RFC 5794, appendix A.1: the 128-bit key
    #[test]
    fn ecb_gives_the_standard_example() {
        let algo = DefaultAlgoBuilder::default().build();
        let key = KeyOwned::new(unhex("000102030405060708090a0b0c0d0e0f"));
        let output = algo
            .cipher()
            .encrypt_by_name(
                "ARIA/ECB/NOPADDING",
                &key,
                &unhex("00112233445566778899aabbccddeeff"),
            )
            .unwrap();
        assert_eq!(output, unhex("d718fbd6ab644c739da95f3be6451778"));
    }

    #[test]
    fn there_are_twenty_rows_with_openpgp_cfb_and_cts_found_by_their_oids() {
        let algo = DefaultAlgoBuilder::default().build();
        let rows = algo
            .cipher()
            .algorithms()
            .filter(|entry| entry.name().starts_with("ARIA/"))
            .count();
        assert_eq!(rows, 20);
        for (oid, name) in [
            ("1.2.410.200046.1.1.1", "ARIA/ECB/PKCS7PADDING"),
            ("1.2.410.200046.1.1.6", "ARIA/ECB/PKCS7PADDING"),
            ("1.2.410.200046.1.1.11", "ARIA/ECB/PKCS7PADDING"),
            ("1.2.410.200046.1.1.2", "ARIA/CBC/PKCS7PADDING"),
            ("1.2.410.200046.1.1.7", "ARIA/CBC/PKCS7PADDING"),
            ("1.2.410.200046.1.1.12", "ARIA/CBC/PKCS7PADDING"),
            ("1.2.410.200046.1.1.3", "ARIA/CFB/NOPADDING"),
            ("1.2.410.200046.1.1.8", "ARIA/CFB/NOPADDING"),
            ("1.2.410.200046.1.1.13", "ARIA/CFB/NOPADDING"),
            ("1.2.410.200046.1.1.4", "ARIA/OFB/NOPADDING"),
            ("1.2.410.200046.1.1.9", "ARIA/OFB/NOPADDING"),
            ("1.2.410.200046.1.1.14", "ARIA/OFB/NOPADDING"),
            ("1.2.410.200046.1.1.5", "ARIA/CTR/NOPADDING"),
            ("1.2.410.200046.1.1.10", "ARIA/CTR/NOPADDING"),
            ("1.2.410.200046.1.1.15", "ARIA/CTR/NOPADDING"),
        ] {
            let by_oid = algo.cipher().get_by_oid(&oid.parse().unwrap()).unwrap();
            let by_name = algo.cipher().get_by_name(name).unwrap();
            assert_eq!(by_oid.block_size(), by_name.block_size(), "{oid}");
        }
    }
}
