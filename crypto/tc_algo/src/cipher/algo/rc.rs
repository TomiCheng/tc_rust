#[cfg(any(feature = "rc2", feature = "rc5", feature = "rc5-64"))]
use core::fmt;

#[cfg(any(feature = "rc2", feature = "rc5", feature = "rc5-64"))]
use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};
#[cfg(feature = "rc6")]
use tc_rc_cipher::Rc6Engine;
#[cfg(feature = "rc5")]
use tc_rc_cipher::Rc532Engine;
#[cfg(feature = "rc5-64")]
use tc_rc_cipher::Rc564Engine;
#[cfg(any(feature = "rc5", feature = "rc5-64"))]
use tc_rc_cipher::{RC5_DEFAULT_ROUNDS, Rc5ParamsRef};
#[cfg(feature = "rc2")]
use tc_rc_cipher::{Rc2Engine, Rc2ParamsRef};

#[cfg(feature = "rc2")]
use super::block::{Mode, Padding};
use super::block::{Rand, block_cipher, block_rows};
use crate::DefaultAlgoContext;
use crate::cipher::CipherEntry;

// The rows of RC2, RC5 and RC6, as in Bouncy Castle's CipherUtilities: each mode with each padding
// it takes. RC2's OID is RSA's for CBC, and the others have none
#[cfg(feature = "rc2")]
pub(super) fn rc2(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    block_rows(
        &["RC2"],
        block_cipher!(Keyed(Rc2Engine::new())),
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
        block_cipher!(Keyed(Rc532Engine::new())),
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
        block_cipher!(Keyed(Rc564Engine::new())),
        rand,
        &[],
    )
}

#[cfg(feature = "rc6")]
pub(super) fn rc6(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    block_rows(&["RC6"], block_cipher!(Rc6Engine::new()), rand, &[])
}

// An RC2 or RC5 engine keyed by a plain key, as Bouncy Castle's engines take a KeyParameter: RC2
// with an effective key size of the whole key, RC5 with 12 rounds. Their own engines take only
// params of their own
#[cfg(any(feature = "rc2", feature = "rc5", feature = "rc5-64"))]
struct Keyed<E>(E);

#[cfg(any(feature = "rc2", feature = "rc5", feature = "rc5-64"))]
impl<E: BlockCipher<Error = BlockError>> BlockCipher for Keyed<E> {
    type Error = BlockError;

    fn block_size(&self) -> usize {
        self.0.block_size()
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        self.0.process_block(input, output)
    }
}

#[cfg(feature = "rc2")]
impl<P: KeyParams + ?Sized> BlockCipherInit<P> for Keyed<Rc2Engine> {
    type Error = InitError;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        self.0.init(direction, &Rc2ParamsRef::new(params.key()))
    }
}

#[cfg(feature = "rc5")]
impl<P: KeyParams + ?Sized> BlockCipherInit<P> for Keyed<Rc532Engine> {
    type Error = InitError;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let params = Rc5ParamsRef::new(params.key(), RC5_DEFAULT_ROUNDS);
        self.0.init(direction, &params)
    }
}

#[cfg(feature = "rc5-64")]
impl<P: KeyParams + ?Sized> BlockCipherInit<P> for Keyed<Rc564Engine> {
    type Error = InitError;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let params = Rc5ParamsRef::new(params.key(), RC5_DEFAULT_ROUNDS);
        self.0.init(direction, &params)
    }
}

#[cfg(any(feature = "rc2", feature = "rc5", feature = "rc5-64"))]
impl<E: fmt::Display> fmt::Display for Keyed<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
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
        assert_eq!(rows("RC2/"), 17);

        let algo = DefaultAlgoBuilder::default().build();
        let by_oid = algo
            .cipher()
            .get_by_oid(&"1.2.840.113549.3.2".parse().unwrap())
            .unwrap();
        assert_eq!(by_oid.block_size(), 8);
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
        assert_eq!(rows("RC5/"), 17);
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
        assert_eq!(rows("RC5-64/"), 17);
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
        assert_eq!(rows("RC6/"), 17);
    }
}
