use tc_twofish::TwofishEngine;

use super::block::{Rand, block_cipher, block_rows};
use crate::DefaultAlgoContext;
use crate::cipher::CipherEntry;

// The rows of Twofish. Bouncy Castle's CipherUtilities gives it no OID, as in Bouncy Castle's CipherUtilities: each mode with each padding it
// takes
pub(super) fn twofish(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    block_rows(&["TWOFISH"], block_cipher!(TwofishEngine::new()), rand, &[])
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

    // The Twofish paper: the zero 128-bit key and block
    #[test]
    fn ecb_gives_the_standard_example() {
        let algo = DefaultAlgoBuilder::default().build();
        let key = KeyOwned::new(unhex("00000000000000000000000000000000"));
        let output = algo
            .cipher()
            .encrypt_by_name(
                "TWOFISH/ECB/NOPADDING",
                &key,
                &unhex("00000000000000000000000000000000"),
            )
            .unwrap();
        assert_eq!(output, unhex("9f589f5cf6122c32b6bfec2f2ae8c35a"));
    }

    #[test]
    fn there_are_twenty_rows_with_openpgp_cfb_and_cts_found_by_their_oids() {
        let algo = DefaultAlgoBuilder::default().build();
        let rows = algo
            .cipher()
            .algorithms()
            .filter(|entry| entry.name().starts_with("TWOFISH/"))
            .count();
        assert_eq!(rows, 20);
    }
}
