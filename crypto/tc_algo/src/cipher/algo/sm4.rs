use tc_sm4::Sm4Engine;

use super::block::{Rand, block_cipher, block_rows};
use crate::DefaultAlgoContext;
use crate::cipher::CipherEntry;

// The rows of SM4, of GB/T 32907-2016. Bouncy Castle's CipherUtilities gives it no OID, as in Bouncy Castle's CipherUtilities: each mode with each padding it
// takes
pub(super) fn sm4(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    block_rows(&["SM4"], block_cipher!(Sm4Engine::new()), rand, &[])
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

    // GB/T 32907-2016, appendix A.1
    #[test]
    fn ecb_gives_the_standard_example() {
        let algo = DefaultAlgoBuilder::default().build();
        let key = KeyOwned::new(unhex("0123456789abcdeffedcba9876543210"));
        let output = algo
            .cipher()
            .encrypt_by_name(
                "SM4/ECB/NOPADDING",
                &key,
                &unhex("0123456789abcdeffedcba9876543210"),
            )
            .unwrap();
        assert_eq!(output, unhex("681edf34d206965e86b3e94f536e4246"));
    }

    #[test]
    fn there_are_eighteen_rows_with_openpgp_cfb_found_by_their_oids() {
        let algo = DefaultAlgoBuilder::default().build();
        let rows = algo
            .cipher()
            .algorithms()
            .filter(|entry| entry.name().starts_with("SM4/"))
            .count();
        assert_eq!(rows, 18);
    }
}
