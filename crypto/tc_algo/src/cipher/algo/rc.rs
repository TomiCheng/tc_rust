#[cfg(feature = "rc6")]
use tc_rc_cipher::Rc6Engine;
#[cfg(feature = "rc5")]
use tc_rc_cipher::Rc532Engine;
#[cfg(feature = "rc5-64")]
use tc_rc_cipher::Rc564Engine;
#[cfg(any(feature = "rc5", feature = "rc5-64"))]
use tc_rc_cipher::{RC5_DEFAULT_ROUNDS, Rc5ParamsOwned, Rc5ParamsRef};
#[cfg(feature = "rc2")]
use tc_rc_cipher::{Rc2Engine, Rc2ParamsOwned, Rc2ParamsRef};

#[cfg(feature = "rc2")]
use super::block::{Mode, Padding};
use super::block::{Rand, block_cipher, block_rows};
#[cfg(any(feature = "rc2", feature = "rc5", feature = "rc5-64"))]
use super::buffered::Own;
#[cfg(any(feature = "rc2", feature = "rc5", feature = "rc5-64"))]
use super::keyed::{Keyed, keyed};
use crate::DefaultAlgoContext;
use crate::cipher::CipherEntry;

// The rows of RC2, RC5 and RC6, as in Bouncy Castle's CipherUtilities: each mode with each padding
// it takes. RC2's OID is RSA's for CBC, and the others have none. RC2 and RC5 take a bare key, as
// Bouncy Castle's KeyParameter, or their own params, as its RC2Parameters and RC5Parameters: an
// Rc2ParamsOwned or Rc5ParamsOwned in ECB and a ParamsWithIvOwned of one in the other modes
#[cfg(feature = "rc2")]
pub(super) fn rc2(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    block_rows(
        &["RC2"],
        block_cipher!(Keyed(Rc2Engine::new()), Own<Rc2ParamsOwned>),
        rand,
        &[(Mode::Cbc, Padding::Pkcs7, &["1.2.840.113549.3.2"])],
    )
}

// RC5 with 32-bit words, also named RC5-32
#[cfg(feature = "rc5")]
pub(super) fn rc5(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    block_rows(
        &["RC5", "RC5-32"],
        block_cipher!(Keyed(Rc532Engine::new()), Own<Rc5ParamsOwned>),
        rand,
        &[],
    )
}

// RC5 with 64-bit words, and so a block of 16 bytes
#[cfg(feature = "rc5-64")]
pub(super) fn rc5_64(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    block_rows(
        &["RC5-64"],
        block_cipher!(Keyed(Rc564Engine::new()), Own<Rc5ParamsOwned>),
        rand,
        &[],
    )
}

#[cfg(feature = "rc6")]
pub(super) fn rc6(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    block_rows(&["RC6"], block_cipher!(Rc6Engine::new()), rand, &[])
}

#[cfg(feature = "rc2")]
keyed!(Rc2Engine, Rc2ParamsOwned, |key| Rc2ParamsRef::new(key));
#[cfg(feature = "rc5")]
keyed!(Rc532Engine, Rc5ParamsOwned, |key| Rc5ParamsRef::new(
    key,
    RC5_DEFAULT_ROUNDS
));
#[cfg(feature = "rc5-64")]
keyed!(Rc564Engine, Rc5ParamsOwned, |key| Rc5ParamsRef::new(
    key,
    RC5_DEFAULT_ROUNDS
));

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

    fn ecb(name: &str, key: &str, block: &str) -> Vec<u8> {
        let algo = DefaultAlgoBuilder::default().build();
        algo.cipher()
            .encrypt_by_name(name, &KeyOwned::new(unhex(key)), &unhex(block))
            .unwrap()
    }

    fn rows(prefix: &str) -> usize {
        let algo = DefaultAlgoBuilder::default().build();
        algo.cipher()
            .algorithms()
            .filter(|entry| entry.name().starts_with(prefix))
            .count()
    }

    // RFC 2268, section 5: an 8-byte key of all ones, with an effective size of its whole 64 bits
    #[cfg(feature = "rc2")]
    #[test]
    fn rc2_gives_the_example_of_rfc_2268_with_the_key_s_whole_size() {
        let output = ecb("RC2/ECB/NOPADDING", "ffffffffffffffff", "ffffffffffffffff");
        assert_eq!(output, unhex("278b27e42e2f0d49"));
        assert_eq!(rows("RC2/"), 19);

        let algo = DefaultAlgoBuilder::default().build();
        let by_oid = algo
            .cipher()
            .get_by_oid(&"1.2.840.113549.3.2".parse().unwrap())
            .unwrap();
        assert_eq!(by_oid.block_size(), 8);
    }

    // RFC 2268, section 5: a 16-byte key with an effective key size of 64 bits, through RC2's own
    // params in ECB, and alone in CBC with an IV of zeros, which gives the same first block
    #[cfg(feature = "rc2")]
    #[test]
    fn rc2_takes_its_effective_key_size_from_its_own_params_in_every_mode() {
        use crate::params::{ParamsWithIvOwned, Rc2ParamsOwned};

        let key = unhex("88bca90e90875a7f0f79c384627bafb2");
        let block = unhex("0000000000000000");
        let expected = unhex("1a807d272bbe5db1");
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();

        let own = Rc2ParamsOwned::with_effective_key_bits(key.clone(), 64);
        let ecb = ciphers
            .encrypt_by_name("RC2/ECB/NOPADDING", &own, &block)
            .unwrap();
        assert_eq!(ecb, expected);

        let with_iv = ParamsWithIvOwned::new(
            Rc2ParamsOwned::with_effective_key_bits(key.clone(), 64),
            vec![0; 8],
        );
        let cbc = ciphers
            .encrypt_by_name("RC2/CBC/NOPADDING", &with_iv, &block)
            .unwrap();
        assert_eq!(cbc, expected);
        let recovered = ciphers
            .decrypt_by_name("RC2/CBC/NOPADDING", &with_iv, &cbc)
            .unwrap();
        assert_eq!(recovered, block);

        // A bare key takes its whole length, 128 bits, as before, which RFC 2268 also gives
        let bare = ciphers
            .encrypt_by_name("RC2/ECB/NOPADDING", &KeyOwned::new(key), &block)
            .unwrap();
        assert_eq!(bare, unhex("2269552ab0f85ca6"));
    }

    #[cfg(feature = "rc2")]
    #[test]
    fn rc2_refuses_its_own_params_with_an_iv_of_another_length_than_a_block() {
        use crate::ErrorKind;
        use crate::params::{ParamsWithIvOwned, Rc2ParamsOwned};

        let algo = DefaultAlgoBuilder::default().build();
        let params = ParamsWithIvOwned::new(Rc2ParamsOwned::new(vec![0x42; 16]), vec![0; 7]);
        let error = algo
            .cipher()
            .encrypt_by_name("RC2/CBC/PKCS7PADDING", &params, b"message")
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }

    // RC5's own params give it its rounds: 12 gives what a bare key gives, 16 something else, and
    // CTR takes them with an IV
    #[cfg(feature = "rc5")]
    #[test]
    fn rc5_takes_its_rounds_from_its_own_params() {
        use crate::params::{ParamsWithIvOwned, Rc5ParamsOwned};

        let key = unhex("000102030405060708090a0b0c0d0e0f");
        let block = unhex("0011223344556677");
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();
        let encrypt = |params: &dyn crate::Params| {
            ciphers
                .encrypt_by_name("RC5/ECB/NOPADDING", params, &block)
                .unwrap()
        };

        let bare = encrypt(&KeyOwned::new(key.clone()));
        assert_eq!(encrypt(&Rc5ParamsOwned::new(key.clone(), 12)), bare);
        assert_ne!(encrypt(&Rc5ParamsOwned::new(key.clone(), 16)), bare);

        let message = b"a message of no particular length";
        let with_iv = ParamsWithIvOwned::new(Rc5ParamsOwned::new(key, 16), vec![0x24; 8]);
        let sealed = ciphers
            .encrypt_by_name("RC5/CTR/NOPADDING", &with_iv, message)
            .unwrap();
        let opened = ciphers
            .decrypt_by_name("RC5/CTR/NOPADDING", &with_iv, &sealed)
            .unwrap();
        assert_eq!(opened, message);
    }

    // Rivest's RC5 paper: RC5-32/12/16 with the zero key and block
    #[cfg(feature = "rc5")]
    #[test]
    fn rc5_gives_the_example_of_rivest_with_12_rounds() {
        let key = "00000000000000000000000000000000";
        for name in ["RC5/ECB/NOPADDING", "RC5-32/ECB/NOPADDING"] {
            assert_eq!(
                ecb(name, key, "0000000000000000"),
                unhex("21a5dbee154b8f6d"),
                "{name}"
            );
        }
        assert_eq!(rows("RC5/"), 19);
    }

    // RC5-64 has no published example to hand: the row gives what the engine gives with 12 rounds
    #[cfg(feature = "rc5-64")]
    #[test]
    fn rc5_64_gives_what_its_engine_gives_with_12_rounds() {
        use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
        use tc_rc_cipher::{Rc5ParamsRef, Rc564Engine};

        let key = unhex("000102030405060708090a0b0c0d0e0f");
        let block = unhex("00112233445566778899aabbccddeeff");
        let mut engine = Rc564Engine::new();
        engine
            .init(CipherDirection::Encrypt, &Rc5ParamsRef::new(&key, 12))
            .unwrap();
        let mut expected = vec![0; 16];
        engine.process_block(&block, &mut expected).unwrap();

        assert_eq!(
            ecb(
                "RC5-64/ECB/NOPADDING",
                "000102030405060708090a0b0c0d0e0f",
                "00112233445566778899aabbccddeeff"
            ),
            expected
        );
        assert_eq!(rows("RC5-64/"), 18);
    }

    // The RC6 paper: the zero 128-bit key and block
    #[cfg(feature = "rc6")]
    #[test]
    fn rc6_gives_the_example_of_its_paper() {
        let output = ecb(
            "RC6/ECB/NOPADDING",
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
        );
        assert_eq!(output, unhex("8fc3a53656b1f778c129df4e9848a41e"));
        assert_eq!(rows("RC6/"), 18);
    }
}
