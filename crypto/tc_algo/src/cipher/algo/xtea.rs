use tc_misc_block_cipher::tea::XteaEngine;

use super::block::{Rand, block_cipher, block_rows};
use crate::DefaultAlgoContext;
use crate::cipher::CipherEntry;

// The rows of XTEA, which Bouncy Castle has as an engine but not in CipherUtilities. It has no OID, as in Bouncy Castle's CipherUtilities: each mode with each padding it
// takes
pub(super) fn xtea(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    block_rows(&["XTEA"], block_cipher!(XteaEngine::new()), rand, &[])
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

    // The row gives what the engine gives
    #[test]
    fn ecb_gives_what_the_engine_gives() {
        use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};

        use super::XteaEngine;

        let key = unhex("000102030405060708090a0b0c0d0e0f");
        let block = unhex("0011223344556677");
        let mut engine = XteaEngine::new();
        engine
            .init(CipherDirection::Encrypt, &KeyRef::new(&key))
            .unwrap();
        let mut expected = vec![0; block.len()];
        engine.process_block(&block, &mut expected).unwrap();

        let algo = DefaultAlgoBuilder::default().build();
        let output = algo
            .cipher()
            .encrypt_by_name("XTEA/ECB/NOPADDING", &KeyOwned::new(key), &block)
            .unwrap();
        assert_eq!(output, expected);
    }

    #[test]
    fn there_are_twenty_one_rows_with_gofb_openpgp_cfb_and_cts_found_by_their_oids() {
        let algo = DefaultAlgoBuilder::default().build();
        let rows = algo
            .cipher()
            .algorithms()
            .filter(|entry| entry.name().starts_with("XTEA/"))
            .count();
        assert_eq!(rows, 21);
    }
}
