use tc_cast::Cast6Engine;

use super::block::{Rand, block_cipher, block_rows};
use crate::DefaultAlgoContext;
use crate::cipher::CipherEntry;

// The rows of CAST6, of RFC 2612. Bouncy Castle's CipherUtilities gives it no OID, as in Bouncy Castle's CipherUtilities: each mode with each padding it
// takes
pub(super) fn cast6(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    block_rows(&["CAST6"], block_cipher!(Cast6Engine::new()), rand, &[])
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

    // RFC 2612, appendix A: the 128-bit key
    #[test]
    fn ecb_gives_the_standard_example() {
        let algo = DefaultAlgoBuilder::default().build();
        let key = KeyOwned::new(unhex("2342bb9efa38542c0af75647f29f615d"));
        let output = algo
            .cipher()
            .encrypt_by_name(
                "CAST6/ECB/NOPADDING",
                &key,
                &unhex("00000000000000000000000000000000"),
            )
            .unwrap();
        assert_eq!(output, unhex("c842a08972b43d20836c91d1b7530f6b"));
    }

    #[test]
    fn there_are_twenty_rows_with_openpgp_cfb_and_cts_found_by_their_oids() {
        let algo = DefaultAlgoBuilder::default().build();
        let rows = algo
            .cipher()
            .algorithms()
            .filter(|entry| entry.name().starts_with("CAST6/"))
            .count();
        assert_eq!(rows, 20);
    }
}
