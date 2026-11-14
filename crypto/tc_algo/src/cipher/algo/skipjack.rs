use tc_misc_block_cipher::skipjack::SkipjackEngine;

use super::block::{Rand, block_cipher, block_rows};
use crate::DefaultAlgoContext;
use crate::cipher::CipherEntry;

// The rows of Skipjack. It has no OID, as in Bouncy Castle's CipherUtilities: each mode with each padding it
// takes
pub(super) fn skipjack(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    block_rows(
        &["SKIPJACK"],
        block_cipher!(SkipjackEngine::new()),
        rand,
        &[],
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

    // The NSA's Skipjack specification
    #[test]
    fn ecb_gives_the_standard_example() {
        let algo = DefaultAlgoBuilder::default().build();
        let key = KeyOwned::new(unhex("00998877665544332211"));
        let output = algo
            .cipher()
            .encrypt_by_name("SKIPJACK/ECB/NOPADDING", &key, &unhex("33221100ddccbbaa"))
            .unwrap();
        assert_eq!(output, unhex("2587cae27a12d300"));
    }

    #[test]
    fn there_are_twenty_one_rows_with_gofb_openpgp_cfb_and_cts_found_by_their_oids() {
        let algo = DefaultAlgoBuilder::default().build();
        let rows = algo
            .cipher()
            .algorithms()
            .filter(|entry| entry.name().starts_with("SKIPJACK/"))
            .count();
        assert_eq!(rows, 21);
    }
}
