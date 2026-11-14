#[cfg(feature = "threefish-256")]
use tc_threefish::Threefish256Engine;
#[cfg(feature = "threefish-512")]
use tc_threefish::Threefish512Engine;
#[cfg(feature = "threefish-1024")]
use tc_threefish::Threefish1024Engine;
use tc_threefish::{ThreefishParamsOwned, ThreefishParamsRef};

use super::block::{Rand, block_cipher, block_rows};
use super::buffered::Own;
use super::keyed::{Keyed, keyed};
use crate::DefaultAlgoContext;
use crate::cipher::CipherEntry;

#[cfg(feature = "threefish-256")]
keyed!(Threefish256Engine, ThreefishParamsOwned, |key| {
    ThreefishParamsRef::new(key)
});
#[cfg(feature = "threefish-512")]
keyed!(Threefish512Engine, ThreefishParamsOwned, |key| {
    ThreefishParamsRef::new(key)
});
#[cfg(feature = "threefish-1024")]
keyed!(Threefish1024Engine, ThreefishParamsOwned, |key| {
    ThreefishParamsRef::new(key)
});

// The rows of Threefish, as in Bouncy Castle's CipherUtilities: each mode with each padding it
// takes, for a block and key of 256, 512 or 1024 bits. A bare key gives a tweak of zeros, as Bouncy
// Castle gives a KeyParameter; a ThreefishParamsOwned gives a tweak of its own, alone in ECB and in
// a ParamsWithIvOwned in the other modes. They have no OIDs
#[cfg(feature = "threefish-256")]
pub(super) fn threefish_256(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    block_rows(
        &["THREEFISH-256"],
        block_cipher!(Keyed(Threefish256Engine::new()), Own<ThreefishParamsOwned>),
        rand,
        &[],
    )
}

#[cfg(feature = "threefish-512")]
pub(super) fn threefish_512(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    block_rows(
        &["THREEFISH-512"],
        block_cipher!(Keyed(Threefish512Engine::new()), Own<ThreefishParamsOwned>),
        rand,
        &[],
    )
}

#[cfg(feature = "threefish-1024")]
pub(super) fn threefish_1024(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    block_rows(
        &["THREEFISH-1024"],
        block_cipher!(Keyed(Threefish1024Engine::new()), Own<ThreefishParamsOwned>),
        rand,
        &[],
    )
}

#[cfg(test)]
mod tests {
    use crate::params::{KeyOwned, ParamsWithIvOwned, ThreefishParamsOwned};
    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind};

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn rows(prefix: &str) -> usize {
        let algo = DefaultAlgoBuilder::default().build();
        algo.cipher()
            .algorithms()
            .filter(|entry| entry.name().starts_with(prefix))
            .count()
    }

    // The Threefish-256 vectors of the Skein reference, as tc_threefish tests them: a bare key with
    // a tweak of zeros, and own params with a tweak
    #[cfg(feature = "threefish-256")]
    #[test]
    fn threefish_256_takes_a_tweak_of_zeros_or_its_own() {
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();

        let bare = ciphers
            .encrypt_by_name(
                "THREEFISH-256/ECB/NOPADDING",
                &KeyOwned::new(vec![0; 32]),
                &[0; 32],
            )
            .unwrap();
        assert_eq!(
            bare,
            unhex("84da2a1f8beaee947066ae3e3103f1ad536db1f4a1192495116b9f3ce6133fd8")
        );

        let key = unhex("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f");
        let tweak = unhex("000102030405060708090a0b0c0d0e0f");
        let block = unhex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0");
        let expected = unhex("e0d091ff0eea8fdfc98192e62ed80ad59d865d08588df476657056b5955e97df");
        let own = ThreefishParamsOwned::with_tweak(key.clone(), tweak.clone());
        let ecb = ciphers
            .encrypt_by_name("THREEFISH-256/ECB/NOPADDING", &own, &block)
            .unwrap();
        assert_eq!(ecb, expected);

        // CBC with an IV of zeros gives the same first block
        let with_iv =
            ParamsWithIvOwned::new(ThreefishParamsOwned::with_tweak(key, tweak), vec![0; 32]);
        let cbc = ciphers
            .encrypt_by_name("THREEFISH-256/CBC/NOPADDING", &with_iv, &block)
            .unwrap();
        assert_eq!(cbc, expected);
        assert_eq!(rows("THREEFISH-256/"), 17);
    }

    #[cfg(feature = "threefish-256")]
    #[test]
    fn a_tweak_of_another_length_is_invalid_params() {
        let algo = DefaultAlgoBuilder::default().build();
        let own = ThreefishParamsOwned::with_tweak(vec![0; 32], vec![0; 8]);
        let error = algo
            .cipher()
            .encrypt_by_name("THREEFISH-256/ECB/NOPADDING", &own, &[0; 32])
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }

    // The wider blocks take their own params with an IV of one block and decrypt back
    #[cfg(all(feature = "threefish-512", feature = "threefish-1024"))]
    #[test]
    fn threefish_512_and_1024_take_their_own_params_with_an_iv_and_decrypt_back() {
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();
        let message = b"a message longer than one block of Threefish-512, padded to two";
        for (name, bytes) in [
            ("THREEFISH-512/CBC/PKCS7PADDING", 64),
            ("THREEFISH-1024/CBC/PKCS7PADDING", 128),
        ] {
            let params = ParamsWithIvOwned::new(
                ThreefishParamsOwned::with_tweak(vec![0x42; bytes], vec![0x24; 16]),
                vec![0x5a; bytes],
            );
            let sealed = ciphers.encrypt_by_name(name, &params, message).unwrap();
            let opened = ciphers.decrypt_by_name(name, &params, &sealed).unwrap();
            assert_eq!(opened, message, "{name}");
        }
        assert_eq!(rows("THREEFISH-512/"), 17);
        assert_eq!(rows("THREEFISH-1024/"), 17);
    }
}
