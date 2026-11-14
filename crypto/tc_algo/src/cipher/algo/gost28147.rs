use tc_gost28147::{Gost28147Engine, Gost28147ParamsOwned, Gost28147ParamsRef};

use super::block::{Mode, Padding, Rand, block_cipher, block_rows};
use super::buffered::Own;
use super::keyed::{Keyed, keyed};
use crate::DefaultAlgoContext;
use crate::cipher::CipherEntry;

keyed!(Gost28147Engine, Gost28147ParamsOwned, |key| {
    Gost28147ParamsRef::new(key)
});

// The rows of GOST 28147-89, as in Bouncy Castle's CipherUtilities: each mode with each padding it
// takes, named GOST28147, GOST and GOST-28147. A bare key gives the engine its default S-box; a
// Gost28147ParamsOwned gives it one of its own, alone in ECB and in a ParamsWithIvOwned in the
// other modes. Bouncy Castle gives CryptoPro's id-Gost28147-89 (GCFB) to CBC with PKCS#7 padding,
// and so do these rows
pub(super) fn gost28147(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    block_rows(
        &["GOST28147", "GOST", "GOST-28147"],
        block_cipher!(Keyed(Gost28147Engine::new()), Own<Gost28147ParamsOwned>),
        rand,
        &[(Mode::Cbc, Padding::Pkcs7, &["1.2.643.2.2.21"])],
    )
}

#[cfg(test)]
mod tests {
    use crate::params::{Gost28147ParamsOwned, KeyOwned, ParamsWithIvOwned, gost28147_s_box};
    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind};

    const KEY: &str = "546d203368656c326973652073736e62206167796967747473656865202c3d73";

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    // The vectors of tc_gost28147, after Bouncy Castle's Gost28147Test
    #[test]
    fn a_bare_key_takes_the_default_s_box_and_own_params_take_theirs() {
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();

        let bare = ciphers
            .encrypt_by_name(
                "GOST28147/ECB/NOPADDING",
                &KeyOwned::new(unhex(KEY)),
                &unhex("0000000000000000"),
            )
            .unwrap();
        assert_eq!(bare, unhex("1b0bbc32cebcab42"));

        let block = unhex("1234567890abcdef");
        let expected = unhex("c41009dba22ebe35");
        let own = Gost28147ParamsOwned::with_s_box(unhex(KEY), gost28147_s_box::E_A.to_vec());
        let ecb = ciphers
            .encrypt_by_name("GOST/ECB/NOPADDING", &own, &block)
            .unwrap();
        assert_eq!(ecb, expected);

        // CBC with an IV of zeros gives the same first block
        let with_iv = ParamsWithIvOwned::new(
            Gost28147ParamsOwned::with_s_box(unhex(KEY), gost28147_s_box::E_A.to_vec()),
            vec![0; 8],
        );
        let cbc = ciphers
            .encrypt_by_name("GOST-28147/CBC/NOPADDING", &with_iv, &block)
            .unwrap();
        assert_eq!(cbc, expected);
        let recovered = ciphers
            .decrypt_by_name("GOST28147/CBC/NOPADDING", &with_iv, &cbc)
            .unwrap();
        assert_eq!(recovered, block);
    }

    #[test]
    fn the_rows_have_every_mode_and_padding_with_gofb_openpgp_cfb_and_cts_and_bouncy_castle_s_oid()
    {
        let algo = DefaultAlgoBuilder::default().build();
        let rows = algo
            .cipher()
            .algorithms()
            .filter(|entry| entry.name().starts_with("GOST28147/"))
            .count();
        assert_eq!(rows, 21);
        let by_oid = algo
            .cipher()
            .get_by_oid(&"1.2.643.2.2.21".parse().unwrap())
            .unwrap();
        assert_eq!(by_oid.block_size(), 8);
    }

    // Bouncy Castle's GOFB vector with the default S-box, as tc_block_modes tests it. GOFB takes a
    // block of 8 bytes only, so AES has no such row
    #[test]
    fn gofb_gives_bouncy_castle_s_vector_and_only_eight_byte_blocks_have_it() {
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();
        let params = crate::params::KeyWithIvOwned::new(
            unhex("0011223344556677889900112233445566778899001122334455667788990011"),
            unhex("1234567890abcdef"),
        );
        let plaintext = unhex("bc350e71aa113457");
        for name in ["GOST28147/GOFB/NOPADDING", "gost/gofb"] {
            let ciphertext = ciphers.encrypt_by_name(name, &params, &plaintext).unwrap();
            assert_eq!(ciphertext, unhex("8824c124c4fd1430"), "{name}");
            let recovered = ciphers.decrypt_by_name(name, &params, &ciphertext).unwrap();
            assert_eq!(recovered, plaintext, "{name}");
        }
        let error = ciphers.get_by_name("AES/GOFB/NOPADDING").err().unwrap();
        assert_eq!(error.kind(), ErrorKind::UnknownCipher);
    }

    #[test]
    fn an_s_box_of_another_length_is_invalid_params() {
        let algo = DefaultAlgoBuilder::default().build();
        let own = Gost28147ParamsOwned::with_s_box(unhex(KEY), vec![0; 64]);
        let error = algo
            .cipher()
            .encrypt_by_name("GOST28147/ECB/NOPADDING", &own, &[0; 8])
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}
