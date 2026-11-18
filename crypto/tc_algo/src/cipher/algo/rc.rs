#[cfg(feature = "rc-cipher")]
use tc_rc_cipher::Rc6Engine;
#[cfg(feature = "rc-cipher")]
use tc_rc_cipher::Rc532Engine;
#[cfg(feature = "rc-cipher")]
use tc_rc_cipher::Rc564Engine;
#[cfg(feature = "rc-cipher")]
use tc_rc_cipher::{RC5_DEFAULT_ROUNDS, Rc5ParamsOwned, Rc5ParamsRef};
#[cfg(feature = "rc-cipher")]
use tc_rc_cipher::{Rc2Engine, Rc2ParamsOwned, Rc2ParamsRef};

#[cfg(feature = "rc-cipher")]
use super::block::block_rows;
#[cfg(feature = "rc-cipher")]
use super::block::{Mode, Padding, block_rows_with_aliases};
use super::block::{Rand, block_cipher};
#[cfg(feature = "rc-cipher")]
use super::buffered::Own;
#[cfg(feature = "rc-cipher")]
use super::keyed::{Keyed, keyed};
use crate::DefaultAlgoContext;
use crate::cipher::CipherEntry;

// The rows of RC2, RC5 and RC6, as in Bouncy Castle's CipherUtilities: each mode with each padding
// it takes. RC2's OID is RSA's for CBC, and the others have none. RC2 and RC5 take a bare key, as
// Bouncy Castle's KeyParameter, or their own params, as its RC2Parameters and RC5Parameters: an
// Rc2ParamsOwned or Rc5ParamsOwned in ECB and a ParamsWithIvOwned of one in the other modes
#[cfg(feature = "rc-cipher")]
pub(super) fn rc2(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    // CBC with PKCS#7 also has the PBE names and OIDs of PKCS#5's and PKCS#12's RC2, the cipher of
    // those schemes; the 5-byte key of the 40-bit one gives 40 effective bits, as a bare key does
    block_rows_with_aliases(
        &["RC2"],
        block_cipher!(Keyed(Rc2Engine::new()), Own<Rc2ParamsOwned>),
        rand,
        &[(
            Mode::Cbc,
            Padding::Pkcs7,
            &[
                "1.2.840.113549.3.2",
                "1.2.840.113549.1.5.11",
                "1.2.840.113549.1.12.1.5",
                "1.2.840.113549.1.12.1.6",
            ],
        )],
        &[(
            Mode::Cbc,
            Padding::Pkcs7,
            &[
                "PBEWITHSHA1ANDRC2-CBC",
                "PBEWITHSHA1ANDRC2",
                "PBEWITHSHAAND128BITRC2-CBC",
                "PBEWITHSHA1AND128BITRC2-CBC",
                "PBEWITHSHAAND40BITRC2-CBC",
                "PBEWITHSHA1AND40BITRC2-CBC",
            ],
        )],
    )
}

// RC5 with 32-bit words, also named RC5-32
#[cfg(feature = "rc-cipher")]
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
#[cfg(feature = "rc-cipher")]
pub(super) fn rc5_64(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    block_rows(
        &["RC5-64"],
        block_cipher!(Keyed(Rc564Engine::new()), Own<Rc5ParamsOwned>),
        rand,
        &[],
    )
}

#[cfg(feature = "rc-cipher")]
pub(super) fn rc6(context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    let rand: Rand = context.rand();
    block_rows(&["RC6"], block_cipher!(Rc6Engine::new()), rand, &[])
}

#[cfg(feature = "rc-cipher")]
keyed!(Rc2Engine, Rc2ParamsOwned, |key| Rc2ParamsRef::new(key));
#[cfg(feature = "rc-cipher")]
keyed!(Rc532Engine, Rc5ParamsOwned, |key| Rc5ParamsRef::new(
    key,
    RC5_DEFAULT_ROUNDS
));
#[cfg(feature = "rc-cipher")]
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
    #[cfg(feature = "rc-cipher")]
    #[test]
    fn rc2_gives_the_example_of_rfc_2268_with_the_key_s_whole_size() {
        let output = ecb("RC2/ECB/NOPADDING", "ffffffffffffffff", "ffffffffffffffff");
        assert_eq!(output, unhex("278b27e42e2f0d49"));
        assert_eq!(rows("RC2/"), 22);

        let algo = DefaultAlgoBuilder::default().build();
        let by_oid = algo
            .cipher()
            .get_by_oid(&"1.2.840.113549.3.2".parse().unwrap())
            .unwrap();
        assert_eq!(by_oid.block_size(), 8);
    }

    // RFC 2268, section 5: a 16-byte key with an effective key size of 64 bits, through RC2's own
    // params in ECB, and alone in CBC with an IV of zeros, which gives the same first block
    #[cfg(feature = "rc-cipher")]
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

    // CTS in CBC passes RC2's own params on to the engine: 40 effective bits give another
    // ciphertext than the whole key, of the message's length, and decrypt back
    #[cfg(feature = "rc-cipher")]
    #[test]
    fn rc2_takes_its_own_params_through_cts() {
        use crate::params::{ParamsWithIvOwned, Rc2ParamsOwned};

        let key = unhex("88bca90e90875a7f0f79c384627bafb2");
        let message = b"twenty bytes of text";
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();
        let own = ParamsWithIvOwned::new(
            Rc2ParamsOwned::with_effective_key_bits(key.clone(), 40),
            vec![0x24; 8],
        );
        let sealed = ciphers
            .encrypt_by_name("RC2/CBC/WITHCTS", &own, message)
            .unwrap();
        assert_eq!(sealed.len(), message.len());
        let opened = ciphers.decrypt_by_name("RC2/CTS", &own, &sealed).unwrap();
        assert_eq!(opened, message);

        let bare = crate::params::KeyWithIvOwned::new(key, vec![0x24; 8]);
        let whole = ciphers
            .encrypt_by_name("RC2/CBC/WITHCTS", &bare, message)
            .unwrap();
        assert_ne!(whole, sealed);
    }

    #[cfg(feature = "rc-cipher")]
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
    #[cfg(feature = "rc-cipher")]
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
    #[cfg(feature = "rc-cipher")]
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
        assert_eq!(rows("RC5/"), 22);
    }

    // RC5-64 has no published example to hand: the row gives what the engine gives with 12 rounds
    #[cfg(feature = "rc-cipher")]
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
        assert_eq!(rows("RC5-64/"), 26);
    }

    // The RC6 paper: the zero 128-bit key and block
    #[cfg(feature = "rc-cipher")]
    #[test]
    fn rc6_gives_the_example_of_its_paper() {
        let output = ecb(
            "RC6/ECB/NOPADDING",
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
        );
        assert_eq!(output, unhex("8fc3a53656b1f778c129df4e9848a41e"));
        assert_eq!(rows("RC6/"), 26);
    }

    // RC2's own params reach the engine under EAX, the AEAD mode of its 8-byte block: the row gives
    // what EaxBlockCipher gives over Rc2Engine with the same params, and a bare key, which takes
    // the whole key size, something else
    #[cfg(feature = "rc-cipher")]
    #[test]
    fn rc2_takes_its_effective_key_size_from_its_own_params_under_eax() {
        use tc_aead_cipher::{AeadCipher, AeadCipherInit, EaxBlockCipher, ParamsWithAeadRef};
        use tc_block_cipher::CipherDirection;
        use tc_rc_cipher::{Rc2Engine, Rc2ParamsRef};

        use crate::params::{AeadParamsOwned, ParamsWithAeadOwned, Rc2ParamsOwned};

        let key = unhex("88bca90e90875a7f0f79c384627bafb2");
        let (nonce, aad) = (vec![0x24; 8], b"header".to_vec());
        let message = b"a message of no particular length";
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();

        let own = ParamsWithAeadOwned::new(
            Rc2ParamsOwned::with_effective_key_bits(key.clone(), 40),
            nonce.clone(),
            8,
            aad.clone(),
        );
        let sealed = ciphers
            .encrypt_by_name("RC2/EAX/NOPADDING", &own, message)
            .unwrap();

        let rc2 = Rc2ParamsRef::with_effective_key_bits(&key, 40);
        let mut eax = EaxBlockCipher::new(Rc2Engine::new());
        eax.init(
            CipherDirection::Encrypt,
            &ParamsWithAeadRef::new(&rc2, &nonce, 8, &aad),
        )
        .unwrap();
        let mut expected = vec![0; eax.output_len(message.len()).unwrap()];
        let written = eax.process_bytes(message, &mut expected).unwrap();
        let written = written + eax.do_final(&mut expected[written..]).unwrap();
        expected.truncate(written);
        assert_eq!(sealed, expected);

        let opened = ciphers.decrypt_by_name("RC2/EAX", &own, &sealed).unwrap();
        assert_eq!(opened, message);

        let bare = AeadParamsOwned::new(key, nonce, 8, aad);
        let whole = ciphers
            .encrypt_by_name("RC2/EAX/NOPADDING", &bare, message)
            .unwrap();
        assert_ne!(whole, sealed);
    }

    // RC5-64's own params give it its rounds under GCM, CCM, EAX, OCB and KCCM, but GCM-SIV, which
    // derives its message keys from the key bytes, takes only a bare key
    #[cfg(feature = "rc-cipher")]
    #[test]
    fn rc5_64_takes_its_rounds_under_every_aead_mode_but_gcm_siv() {
        use crate::ErrorKind;
        use crate::params::{AeadParamsOwned, ParamsWithAeadOwned, Rc5ParamsOwned};

        let key = unhex("000102030405060708090a0b0c0d0e0f");
        let message = [0x33; 32];
        let algo = DefaultAlgoBuilder::default().build();
        let ciphers = algo.cipher();
        for (name, nonce) in [
            ("RC5-64/GCM/NOPADDING", 12),
            ("RC5-64/CCM/NOPADDING", 12),
            ("RC5-64/EAX/NOPADDING", 12),
            ("RC5-64/OCB/NOPADDING", 12),
            ("RC5-64/KCCM/NOPADDING", 16),
        ] {
            let own = ParamsWithAeadOwned::new(
                Rc5ParamsOwned::new(key.clone(), 16),
                vec![0x24; nonce],
                16,
                Vec::new(),
            );
            let sealed = ciphers.encrypt_by_name(name, &own, &message).unwrap();
            let opened = ciphers.decrypt_by_name(name, &own, &sealed).unwrap();
            assert_eq!(opened, message, "{name}");

            let bare = AeadParamsOwned::new(key.clone(), vec![0x24; nonce], 16, Vec::new());
            let twelve = ciphers.encrypt_by_name(name, &bare, &message).unwrap();
            assert_ne!(twelve, sealed, "{name}");
        }

        let own =
            ParamsWithAeadOwned::new(Rc5ParamsOwned::new(key, 16), vec![0x24; 12], 16, Vec::new());
        let error = ciphers
            .encrypt_by_name("RC5-64/GCM-SIV/NOPADDING", &own, &message)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}
