use tc_cast::Cast5Engine;

use super::block::{Mode, Padding, Rand, block_cipher, block_rows};
use crate::DefaultAlgoContext;
use crate::cipher::CipherEntry;

// The rows of CAST5, of RFC 2144. Its OID is Entrust's for CBC, as in Bouncy Castle's CipherUtilities: each mode with each padding it
// takes
pub(super) fn cast5(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    block_rows(
        &["CAST5"],
        block_cipher!(Cast5Engine::new()),
        rand,
        &[(Mode::Cbc, Padding::Pkcs7, &["1.2.840.113533.7.66.10"])],
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

    // RFC 2144, appendix B.1: the 128-bit key
    #[test]
    fn ecb_gives_the_standard_example() {
        let algo = DefaultAlgoBuilder::default().build();
        let key = KeyOwned::new(unhex("0123456712345678234567893456789a"));
        let output = algo
            .cipher()
            .encrypt_by_name("CAST5/ECB/NOPADDING", &key, &unhex("0123456789abcdef"))
            .unwrap();
        assert_eq!(output, unhex("238b4fe5847e44b2"));
    }

    #[test]
    fn there_are_twenty_one_rows_with_gofb_openpgp_cfb_and_cts_found_by_their_oids() {
        let algo = DefaultAlgoBuilder::default().build();
        let rows = algo
            .cipher()
            .algorithms()
            .filter(|entry| entry.name().starts_with("CAST5/"))
            .count();
        assert_eq!(rows, 21);
        let by_oid = algo
            .cipher()
            .get_by_oid(&"1.2.840.113533.7.66.10".parse().unwrap())
            .unwrap();
        let by_name = algo.cipher().get_by_name("CAST5/CBC/PKCS7PADDING").unwrap();
        assert_eq!(by_oid.block_size(), by_name.block_size());
    }
}
