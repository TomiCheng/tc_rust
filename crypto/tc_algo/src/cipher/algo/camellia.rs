use tc_camellia::CamelliaEngine;

use super::block::{Mode, Padding, Rand, block_cipher, block_rows};
use crate::DefaultAlgoContext;
use crate::cipher::CipherEntry;

// The rows of Camellia, of RFC 3713. Its OIDs are NTT's for CBC with 128-, 192- and 256-bit keys, as in Bouncy Castle's CipherUtilities: each mode with each padding it
// takes
pub(super) fn camellia(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    block_rows(
        &["CAMELLIA"],
        block_cipher!(CamelliaEngine::new()),
        rand,
        &[(
            Mode::Cbc,
            Padding::Pkcs7,
            &[
                "1.2.392.200011.61.1.1.1.2",
                "1.2.392.200011.61.1.1.1.3",
                "1.2.392.200011.61.1.1.1.4",
            ],
        )],
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

    // RFC 3713, appendix A: the 128-bit key
    #[test]
    fn ecb_gives_the_standard_example() {
        let algo = DefaultAlgoBuilder::default().build();
        let key = KeyOwned::new(unhex("0123456789abcdeffedcba9876543210"));
        let output = algo
            .cipher()
            .encrypt_by_name(
                "CAMELLIA/ECB/NOPADDING",
                &key,
                &unhex("0123456789abcdeffedcba9876543210"),
            )
            .unwrap();
        assert_eq!(output, unhex("67673138549669730857065648eabe43"));
    }

    #[test]
    fn there_are_seventeen_rows_found_by_their_oids() {
        let algo = DefaultAlgoBuilder::default().build();
        let rows = algo
            .cipher()
            .algorithms()
            .filter(|entry| entry.name().starts_with("CAMELLIA/"))
            .count();
        assert_eq!(rows, 17);
        for (oid, name) in [
            ("1.2.392.200011.61.1.1.1.2", "CAMELLIA/CBC/PKCS7PADDING"),
            ("1.2.392.200011.61.1.1.1.3", "CAMELLIA/CBC/PKCS7PADDING"),
            ("1.2.392.200011.61.1.1.1.4", "CAMELLIA/CBC/PKCS7PADDING"),
        ] {
            let by_oid = algo.cipher().get_by_oid(&oid.parse().unwrap()).unwrap();
            let by_name = algo.cipher().get_by_name(name).unwrap();
            assert_eq!(by_oid.block_size(), by_name.block_size(), "{oid}");
        }
    }
}
