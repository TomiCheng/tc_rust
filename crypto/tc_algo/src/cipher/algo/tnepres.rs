use tc_serpent::TnepresEngine;

use super::block::{Rand, block_cipher, block_rows};
use crate::DefaultAlgoContext;
use crate::cipher::CipherEntry;

// The rows of Tnepres, Serpent in the byte order of Bouncy Castle's first Serpent. It has no OID, as in Bouncy Castle's CipherUtilities: each mode with each padding it
// takes
pub(super) fn tnepres(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    block_rows(&["TNEPRES"], block_cipher!(TnepresEngine::new()), rand, &[])
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

        let key = unhex("000102030405060708090a0b0c0d0e0f1011121314151617");
        let block = unhex("00112233445566778899aabbccddeeff");
        let mut engine = tc_serpent::TnepresEngine::new();
        engine
            .init(CipherDirection::Encrypt, &KeyRef::new(&key))
            .unwrap();
        let mut expected = vec![0; 16];
        engine.process_block(&block, &mut expected).unwrap();

        let algo = DefaultAlgoBuilder::default().build();
        let output = algo
            .cipher()
            .encrypt_by_name("TNEPRES/ECB/NOPADDING", &KeyOwned::new(key), &block)
            .unwrap();
        assert_eq!(output, expected);
    }

    #[test]
    fn there_are_eighteen_rows_with_openpgp_cfb_found_by_their_oids() {
        let algo = DefaultAlgoBuilder::default().build();
        let rows = algo
            .cipher()
            .algorithms()
            .filter(|entry| entry.name().starts_with("TNEPRES/"))
            .count();
        assert_eq!(rows, 18);
    }
}
