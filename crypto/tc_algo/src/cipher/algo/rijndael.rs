use tc_misc_block_cipher::rijndael::Rijndael128Engine;

use super::block::{Rand, block_cipher, block_rows};
use crate::DefaultAlgoContext;
use crate::cipher::CipherEntry;

// The rows of Rijndael with a block of 16 bytes, as Bouncy Castle's CipherUtilities builds it, which is AES. It has
// no OID, as in Bouncy Castle's CipherUtilities: each mode with each padding it
// takes
pub(super) fn rijndael(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    block_rows(
        &["RIJNDAEL"],
        block_cipher!(Rijndael128Engine::new()),
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

    // FIPS 197, appendix C.1: Rijndael with a 16-byte block is AES
    #[test]
    fn ecb_gives_the_standard_example() {
        let algo = DefaultAlgoBuilder::default().build();
        let key = KeyOwned::new(unhex("000102030405060708090a0b0c0d0e0f"));
        let output = algo
            .cipher()
            .encrypt_by_name(
                "RIJNDAEL/ECB/NOPADDING",
                &key,
                &unhex("00112233445566778899aabbccddeeff"),
            )
            .unwrap();
        assert_eq!(output, unhex("69c4e0d86a7b0430d8cdb78070b4c55a"));
    }

    #[test]
    fn there_are_twenty_rows_with_openpgp_cfb_and_cts_found_by_their_oids() {
        let algo = DefaultAlgoBuilder::default().build();
        let rows = algo
            .cipher()
            .algorithms()
            .filter(|entry| entry.name().starts_with("RIJNDAEL/"))
            .count();
        assert_eq!(rows, 20);
    }
}
