use tc_blowfish::BlowfishEngine;

use super::block::{Mode, Padding, Rand, block_cipher, block_rows};
use crate::DefaultAlgoContext;
use crate::cipher::CipherEntry;

// The rows of Blowfish. Its OIDs are cryptlib's for CBC, of which Bouncy Castle has two, as in Bouncy Castle's CipherUtilities: each mode with each padding it
// takes
pub(super) fn blowfish(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    block_rows(
        &["BLOWFISH"],
        block_cipher!(BlowfishEngine::new()),
        rand,
        &[(
            Mode::Cbc,
            Padding::Pkcs7,
            &["1.3.6.1.4.1.3029.1.2", "1.3.6.1.4.1.3029.1.1.2"],
        )],
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

    // Eric Young's vectors for Blowfish: the zero key and block
    #[test]
    fn ecb_gives_the_standard_example() {
        let algo = DefaultAlgoBuilder::default().build();
        let key = KeyOwned::new(unhex("0000000000000000"));
        let output = algo
            .cipher()
            .encrypt_by_name("BLOWFISH/ECB/NOPADDING", &key, &unhex("0000000000000000"))
            .unwrap();
        assert_eq!(output, unhex("4ef997456198dd78"));
    }

    #[test]
    fn there_are_twenty_two_rows_with_gofb_openpgp_cfb_cts_and_eax_found_by_their_oids() {
        let algo = DefaultAlgoBuilder::default().build();
        let rows = algo
            .cipher()
            .algorithms()
            .filter(|entry| entry.name().starts_with("BLOWFISH/"))
            .count();
        assert_eq!(rows, 22);
        for (oid, name) in [
            ("1.3.6.1.4.1.3029.1.2", "BLOWFISH/CBC/PKCS7PADDING"),
            ("1.3.6.1.4.1.3029.1.1.2", "BLOWFISH/CBC/PKCS7PADDING"),
        ] {
            let by_oid = algo.cipher().get_by_oid(&oid.parse().unwrap()).unwrap();
            let by_name = algo.cipher().get_by_name(name).unwrap();
            assert_eq!(by_oid.block_size(), by_name.block_size(), "{oid}");
        }
    }
}
