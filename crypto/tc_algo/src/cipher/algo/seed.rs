use tc_seed::SeedEngine;

use super::block::{Mode, Padding, Rand, block_cipher, block_rows};
use crate::DefaultAlgoContext;
use crate::cipher::CipherEntry;

// The rows of SEED, of RFC 4269. Its OID is KISA's for CBC, as in Bouncy Castle's CipherUtilities: each mode with each padding it
// takes
pub(super) fn seed(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    block_rows(
        &["SEED"],
        block_cipher!(SeedEngine::new()),
        rand,
        &[(Mode::Cbc, Padding::Pkcs7, &["1.2.410.200004.1.4"])],
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

    // RFC 4269, appendix B.1
    #[test]
    fn ecb_gives_the_standard_example() {
        let algo = DefaultAlgoBuilder::default().build();
        let key = KeyOwned::new(unhex("00000000000000000000000000000000"));
        let output = algo
            .cipher()
            .encrypt_by_name(
                "SEED/ECB/NOPADDING",
                &key,
                &unhex("000102030405060708090a0b0c0d0e0f"),
            )
            .unwrap();
        assert_eq!(output, unhex("5ebac6e0054e166819aff1cc6d346cdb"));
    }

    #[test]
    fn there_are_seventeen_rows_found_by_their_oids() {
        let algo = DefaultAlgoBuilder::default().build();
        let rows = algo
            .cipher()
            .algorithms()
            .filter(|entry| entry.name().starts_with("SEED/"))
            .count();
        assert_eq!(rows, 17);
        let by_oid = algo
            .cipher()
            .get_by_oid(&"1.2.410.200004.1.4".parse().unwrap())
            .unwrap();
        let by_name = algo.cipher().get_by_name("SEED/CBC/PKCS7PADDING").unwrap();
        assert_eq!(by_oid.block_size(), by_name.block_size());
    }
}
