use tc_misc_block_cipher::idea::IdeaEngine;

use super::block::{Mode, Padding, Rand, block_cipher, block_rows};
use crate::DefaultAlgoContext;
use crate::cipher::CipherEntry;

// The rows of IDEA. Its OID is Ascom's for CBC, as in Bouncy Castle's CipherUtilities: each mode with each padding it
// takes
pub(super) fn idea(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    block_rows(
        &["IDEA"],
        block_cipher!(IdeaEngine::new()),
        rand,
        &[(Mode::Cbc, Padding::Pkcs7, &["1.3.6.1.4.1.188.7.1.1.2"])],
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

    // The IDEA paper: key 0001 0002 ... 0008, block 0000 0001 0002 0003
    #[test]
    fn ecb_gives_the_standard_example() {
        let algo = DefaultAlgoBuilder::default().build();
        let key = KeyOwned::new(unhex("00010002000300040005000600070008"));
        let output = algo
            .cipher()
            .encrypt_by_name("IDEA/ECB/NOPADDING", &key, &unhex("0000000100020003"))
            .unwrap();
        assert_eq!(output, unhex("11fbed2b01986de5"));
    }

    #[test]
    fn there_are_twenty_one_rows_with_gofb_openpgp_cfb_and_cts_found_by_their_oids() {
        let algo = DefaultAlgoBuilder::default().build();
        let rows = algo
            .cipher()
            .algorithms()
            .filter(|entry| entry.name().starts_with("IDEA/"))
            .count();
        assert_eq!(rows, 21);
        let by_oid = algo
            .cipher()
            .get_by_oid(&"1.3.6.1.4.1.188.7.1.1.2".parse().unwrap())
            .unwrap();
        let by_name = algo.cipher().get_by_name("IDEA/CBC/PKCS7PADDING").unwrap();
        assert_eq!(by_oid.block_size(), by_name.block_size());
    }
}
