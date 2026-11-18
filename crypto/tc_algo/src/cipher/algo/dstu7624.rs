#[cfg(feature = "dstu7624")]
use tc_dstu7624::Dstu7624Engine128;
#[cfg(feature = "dstu7624")]
use tc_dstu7624::Dstu7624Engine256;
#[cfg(feature = "dstu7624")]
use tc_dstu7624::Dstu7624Engine512;

use super::block::{Rand, block_cipher, block_rows};
use crate::DefaultAlgoContext;
use crate::cipher::CipherEntry;

// The rows of DSTU 7624, Kalyna, the block cipher of Ukraine, by its block in bits: each mode with
// each padding it takes. Bouncy Castle has the engine but no name for it in CipherUtilities, so the
// names are this crate's, after the block as THREEFISH-256's, and carry no OID
#[cfg(feature = "dstu7624")]
pub(super) fn dstu7624_128(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    block_rows(
        &["DSTU7624-128"],
        block_cipher!(Dstu7624Engine128::new()),
        rand,
        &[],
    )
}

#[cfg(feature = "dstu7624")]
pub(super) fn dstu7624_256(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    block_rows(
        &["DSTU7624-256"],
        block_cipher!(Dstu7624Engine256::new()),
        rand,
        &[],
    )
}

#[cfg(feature = "dstu7624")]
pub(super) fn dstu7624_512(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    block_rows(
        &["DSTU7624-512"],
        block_cipher!(Dstu7624Engine512::new()),
        rand,
        &[],
    )
}

#[cfg(test)]
mod tests {
    use crate::params::key::KeyOwned;
    use crate::{AlgoBuilder, DefaultAlgoBuilder};

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn ecb(name: &str, key: &str, block: &str) -> Vec<u8> {
        let algo = DefaultAlgoBuilder::default().build();
        algo.cipher()
            .encrypt_by_name(name, &KeyOwned::new(unhex(key)), &unhex(block))
            .unwrap()
    }

    fn modes(prefix: &str) -> Vec<String> {
        let algo = DefaultAlgoBuilder::default().build();
        let mut modes: Vec<String> = algo
            .cipher()
            .algorithms()
            .filter(|entry| entry.name().starts_with(prefix))
            .map(|entry| entry.name().split('/').nth(1).unwrap().to_string())
            .collect();
        modes.dedup();
        modes
    }

    // The examples of DSTU 7624:2014, as tc_dstu7624 tests them, and the AEAD modes of a 16-byte
    // block
    #[cfg(feature = "dstu7624")]
    #[test]
    fn dstu7624_128_gives_the_examples_of_the_standard_and_has_every_aead_mode() {
        let output = ecb(
            "DSTU7624-128/ECB/NOPADDING",
            "000102030405060708090a0b0c0d0e0f",
            "101112131415161718191a1b1c1d1e1f",
        );
        assert_eq!(output, unhex("81bf1c7d779bac20e1c9ea39b4d2ad06"));
        let output = ecb(
            "DSTU7624-128/ECB/NOPADDING",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "202122232425262728292a2b2c2d2e2f",
        );
        assert_eq!(output, unhex("58ec3e091000158a1148f7166f334f14"));

        let modes = modes("DSTU7624-128/");
        for mode in ["GCM", "CCM", "EAX", "OCB", "GCM-SIV", "KCCM"] {
            assert!(modes.iter().any(|m| m == mode), "{mode}");
        }
        assert!(!modes.iter().any(|m| m == "GOFB"));
    }

    // Kalyna-256 and -512 have KCCM, of a block of 32 or 64 bytes, and none of the other AEAD modes
    #[cfg(feature = "dstu7624")]
    #[test]
    fn dstu7624_256_and_512_give_the_examples_of_the_standard_and_have_kccm_alone() {
        let output = ecb(
            "DSTU7624-256/ECB/NOPADDING",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        );
        assert_eq!(
            output,
            unhex("f66e3d570ec92135aedae323dcbd2a8ca03963ec206a0d5a88385c24617fd92c")
        );
        let output = ecb(
            "DSTU7624-512/ECB/NOPADDING",
            concat!(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
            ),
            concat!(
                "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
            ),
        );
        assert_eq!(
            output,
            unhex(concat!(
                "4a26e31b811c356aa61dd6ca0596231a67ba8354aa47f3a13e1deec320eb56b8",
                "95d0f417175bab662fd6f134bb15c86ccb906a26856efeb7c5bc6472940dd9d9"
            ))
        );

        for prefix in ["DSTU7624-256/", "DSTU7624-512/"] {
            let modes = modes(prefix);
            assert!(modes.iter().any(|m| m == "KCCM"), "{prefix}");
            for mode in ["GCM", "CCM", "EAX", "OCB", "GCM-SIV", "GOFB"] {
                assert!(!modes.iter().any(|m| m == mode), "{prefix}{mode}");
            }
        }
    }
}
