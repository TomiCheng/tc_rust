use super::fixed::{Lengths, row};
use super::random::Rule;
use crate::DefaultAlgoContext;
use crate::generate::KeyGeneratorEntry;

// The rows of the keys of the block ciphers but AES128, AES192 and AES256, and but those with
// params of their own, RC2, RC5, GOST 28147 and Threefish, to give to DefaultAlgoBuilder::reg_key_generator.
// Their names, aliases, OIDs and default lengths are those of Bouncy Castle's GeneratorUtilities,
// with DESEDE16 and DESEDE24 besides for the two lengths of DESede; init with a KeyLength sets
// another length the cipher takes. Each is behind the feature of its cipher
pub(super) fn block(context: &DefaultAlgoContext) -> Vec<Box<dyn KeyGeneratorEntry>> {
    let rand = context.rand();
    let mut rows: Vec<Box<dyn KeyGeneratorEntry>> = Vec::new();
    let mut add = |name, aliases: &[&'static str], oids: &[&str], key_len, lengths, rule| {
        rows.push(row(name, aliases, oids, key_len, lengths, rule, rand));
    };
    #[cfg(feature = "aes")]
    add(
        "AES",
        &["AESWRAP"],
        &[],
        24,
        Lengths::Of(&[16, 24, 32]),
        Rule::Random,
    );
    #[cfg(feature = "aria")]
    add(
        "ARIA",
        &[],
        &[],
        32,
        Lengths::Of(&[16, 24, 32]),
        Rule::Random,
    );
    #[cfg(feature = "aria")]
    add(
        "ARIA128",
        &[],
        &[
            "1.2.410.200046.1.1.2",
            "1.2.410.200046.1.1.37",
            "1.2.410.200046.1.1.3",
            "1.2.410.200046.1.1.5",
            "1.2.410.200046.1.1.1",
            "1.2.410.200046.1.1.34",
            "1.2.410.200046.1.1.40",
            "1.2.410.200046.1.1.43",
            "1.2.410.200046.1.1.31",
            "1.2.410.200046.1.1.4",
        ],
        16,
        Lengths::Of(&[16]),
        Rule::Random,
    );
    #[cfg(feature = "aria")]
    add(
        "ARIA192",
        &[],
        &[
            "1.2.410.200046.1.1.7",
            "1.2.410.200046.1.1.38",
            "1.2.410.200046.1.1.8",
            "1.2.410.200046.1.1.10",
            "1.2.410.200046.1.1.6",
            "1.2.410.200046.1.1.35",
            "1.2.410.200046.1.1.41",
            "1.2.410.200046.1.1.44",
            "1.2.410.200046.1.1.32",
            "1.2.410.200046.1.1.9",
        ],
        24,
        Lengths::Of(&[24]),
        Rule::Random,
    );
    #[cfg(feature = "aria")]
    add(
        "ARIA256",
        &[],
        &[
            "1.2.410.200046.1.1.12",
            "1.2.410.200046.1.1.39",
            "1.2.410.200046.1.1.13",
            "1.2.410.200046.1.1.15",
            "1.2.410.200046.1.1.11",
            "1.2.410.200046.1.1.36",
            "1.2.410.200046.1.1.42",
            "1.2.410.200046.1.1.45",
            "1.2.410.200046.1.1.33",
            "1.2.410.200046.1.1.14",
        ],
        32,
        Lengths::Of(&[32]),
        Rule::Random,
    );
    #[cfg(feature = "blowfish")]
    add(
        "BLOWFISH",
        &[],
        &["1.3.6.1.4.1.3029.1.2", "1.3.6.1.4.1.3029.1.1.2"],
        16,
        Lengths::range(4, 56),
        Rule::Random,
    );
    #[cfg(feature = "camellia")]
    add(
        "CAMELLIA",
        &["CAMELLIAWRAP"],
        &[],
        32,
        Lengths::Of(&[16, 24, 32]),
        Rule::Random,
    );
    #[cfg(feature = "camellia")]
    add(
        "CAMELLIA128",
        &[],
        &["1.2.392.200011.61.1.1.1.2", "1.2.392.200011.61.1.1.3.2"],
        16,
        Lengths::Of(&[16]),
        Rule::Random,
    );
    #[cfg(feature = "camellia")]
    add(
        "CAMELLIA192",
        &[],
        &["1.2.392.200011.61.1.1.1.3", "1.2.392.200011.61.1.1.3.3"],
        24,
        Lengths::Of(&[24]),
        Rule::Random,
    );
    #[cfg(feature = "camellia")]
    add(
        "CAMELLIA256",
        &[],
        &["1.2.392.200011.61.1.1.1.4", "1.2.392.200011.61.1.1.3.4"],
        32,
        Lengths::Of(&[32]),
        Rule::Random,
    );
    #[cfg(feature = "cast5")]
    add(
        "CAST5",
        &[],
        &["1.2.840.113533.7.66.10"],
        16,
        Lengths::range(5, 16),
        Rule::Random,
    );
    #[cfg(feature = "cast6")]
    add(
        "CAST6",
        &[],
        &[],
        32,
        Lengths::Of(&[16, 20, 24, 28, 32]),
        Rule::Random,
    );
    #[cfg(feature = "des")]
    add(
        "DES",
        &[],
        &[
            "1.3.14.3.2.7",
            "1.3.14.3.2.9",
            "1.3.14.3.2.6",
            "1.3.14.3.2.8",
        ],
        8,
        Lengths::Of(&[8]),
        Rule::Des,
    );
    #[cfg(feature = "desede")]
    add(
        "DESEDE",
        &["DESEDEWRAP", "TDEA", "DESEDE16"],
        &["1.3.14.3.2.17"],
        16,
        Lengths::Of(&[16, 24]),
        Rule::DesEde,
    );
    #[cfg(feature = "desede")]
    add(
        "DESEDE3",
        &["DESEDE24"],
        &["1.2.840.113549.3.7", "1.2.840.113549.1.9.16.3.6"],
        24,
        Lengths::Of(&[16, 24]),
        Rule::DesEde,
    );
    #[cfg(feature = "idea")]
    add(
        "IDEA",
        &[],
        &["1.3.6.1.4.1.188.7.1.1.2"],
        16,
        Lengths::Of(&[16]),
        Rule::Random,
    );
    #[cfg(feature = "noekeon")]
    add("NOEKEON", &[], &[], 16, Lengths::Of(&[16]), Rule::Random);
    #[cfg(feature = "rc6")]
    add("RC6", &[], &[], 32, Lengths::range(1, 255), Rule::Random);
    #[cfg(feature = "rijndael")]
    add(
        "RIJNDAEL",
        &[],
        &[],
        24,
        Lengths::Of(&[16, 20, 24, 28, 32]),
        Rule::Random,
    );
    #[cfg(feature = "seed")]
    add(
        "SEED",
        &[],
        &["1.2.410.200004.7.1.1.1", "1.2.410.200004.1.4"],
        16,
        Lengths::Of(&[16]),
        Rule::Random,
    );
    #[cfg(feature = "serpent")]
    add(
        "SERPENT",
        &[],
        &[],
        24,
        Lengths::Range {
            min: 4,
            max: 32,
            step: 4,
        },
        Rule::Random,
    );
    #[cfg(feature = "skipjack")]
    add("SKIPJACK", &[], &[], 10, Lengths::Of(&[10]), Rule::Random);
    #[cfg(feature = "sm4")]
    add("SM4", &[], &[], 16, Lengths::Of(&[16]), Rule::Random);
    #[cfg(feature = "tea")]
    add("TEA", &[], &[], 16, Lengths::Of(&[16]), Rule::Random);
    #[cfg(feature = "tnepres")]
    add(
        "TNEPRES",
        &[],
        &[],
        24,
        Lengths::Range {
            min: 4,
            max: 32,
            step: 4,
        },
        Rule::Random,
    );
    #[cfg(feature = "twofish")]
    add(
        "TWOFISH",
        &[],
        &[],
        32,
        Lengths::Of(&[16, 24, 32]),
        Rule::Random,
    );
    #[cfg(feature = "xtea")]
    add("XTEA", &[], &[], 16, Lengths::Of(&[16]), Rule::Random);
    rows
}

#[cfg(test)]
mod tests {
    use crate::params::{KeyOwned, KeyParams};
    use crate::{AlgoBuilder, DefaultAlgoBuilder, Params};

    fn key_of(key: &dyn Params) -> Vec<u8> {
        let key = key.as_any().downcast_ref::<KeyOwned>();
        key.expect("a KeyOwned").key().to_vec()
    }

    // Each name, and each alias, gives a key of Bouncy Castle's length for it
    #[test]
    fn every_row_gives_a_key_of_its_length() {
        let algo = DefaultAlgoBuilder::default().build();
        let generators = algo.key_generator();
        for (name, bytes) in [
            ("AES", 24),
            ("AESWRAP", 24),
            ("ARIA", 32),
            ("ARIA128", 16),
            ("ARIA192", 24),
            ("ARIA256", 32),
            ("BLOWFISH", 16),
            ("CAMELLIA", 32),
            ("CAMELLIA128", 16),
            ("CAMELLIA192", 24),
            ("CAMELLIA256", 32),
            ("CAST5", 16),
            ("CAST6", 32),
            ("DES", 8),
            ("DESEDE", 16),
            ("DESEDE16", 16),
            ("TDEA", 16),
            ("DESEDE3", 24),
            ("DESEDE24", 24),
            ("IDEA", 16),
            ("NOEKEON", 16),
            ("RC6", 32),
            ("RIJNDAEL", 24),
            ("SEED", 16),
            ("SERPENT", 24),
            ("SKIPJACK", 10),
            ("SM4", 16),
            ("TEA", 16),
            ("TNEPRES", 24),
            ("TWOFISH", 32),
            ("XTEA", 16),
        ] {
            let key = generators.generate_by_name(name).unwrap();
            assert_eq!(key_of(key.as_ref()).len(), bytes, "{name}");
        }
    }

    // The OID of a cipher finds the key for it: DES in CBC, three-key DESede in CBC, ARIA-192
    // in GCM
    #[test]
    fn the_oid_of_a_cipher_finds_the_key_for_it() {
        let algo = DefaultAlgoBuilder::default().build();
        let generators = algo.key_generator();
        for (dotted, bytes) in [
            ("1.3.14.3.2.7", 8),
            ("1.2.840.113549.3.7", 24),
            ("1.2.410.200046.1.1.35", 24),
        ] {
            let key = generators
                .generate_by_oid(&dotted.parse().unwrap())
                .unwrap();
            assert_eq!(key_of(key.as_ref()).len(), bytes, "{dotted}");
        }
    }

    // DES and DESede keys have odd parity and are not weak, and a DESede key is not DES again
    #[cfg(all(feature = "des", feature = "desede"))]
    #[test]
    fn des_and_desede_keys_keep_their_rules() {
        let algo = DefaultAlgoBuilder::default().build();
        let generators = algo.key_generator();
        for _ in 0..100 {
            let key = key_of(generators.generate_by_name("DES").unwrap().as_ref());
            assert!(key.iter().all(|byte| byte.count_ones() % 2 == 1));
            assert!(!tc_des::is_weak_key(key.as_slice().try_into().unwrap()));

            for name in ["DESEDE16", "DESEDE24"] {
                let key = key_of(generators.generate_by_name(name).unwrap().as_ref());
                assert!(key.iter().all(|byte| byte.count_ones() % 2 == 1), "{name}");
                assert!(!tc_des::is_weak_ede_key(&key), "{name}");
                assert!(tc_des::is_real_ede_key(&key), "{name}");
            }
        }
    }

    // A generated key goes straight into its cipher
    #[test]
    fn a_generated_key_goes_into_its_cipher() {
        use crate::params::KeyWithIvOwned;

        let algo = DefaultAlgoBuilder::default().build();
        let key = algo.key_generator().generate_by_name("DESEDE24").unwrap();
        let params = KeyWithIvOwned::new(key_of(key.as_ref()), vec![0x24; 8]);
        let sealed = algo
            .cipher()
            .encrypt_by_name("DESEDE/CBC/PKCS7PADDING", &params, b"attack at dawn")
            .unwrap();
        let opened = algo
            .cipher()
            .decrypt_by_name("DESEDE/CBC/PKCS7PADDING", &params, &sealed)
            .unwrap();
        assert_eq!(opened, b"attack at dawn");
    }

    // A length the cipher takes is set, by a range, a set of lengths or a step, and one it does not
    // take is InvalidParams; DES takes 8 alone, and DESede 16 and 24 under either name
    #[test]
    fn init_takes_the_lengths_of_each_cipher() {
        use crate::ErrorKind;
        use crate::params::KeyLength;

        let algo = DefaultAlgoBuilder::default().build();
        let generators = algo.key_generator();
        for (name, good, bad) in [
            ("BLOWFISH", 56, 57),
            ("TWOFISH", 24, 20),
            ("SERPENT", 28, 30),
            ("DES", 8, 16),
            ("DESEDE", 24, 8),
            ("DESEDE3", 16, 32),
            ("ARIA128", 16, 32),
        ] {
            let key = generators
                .generate_by_name_with(name, &KeyLength::new(good))
                .unwrap();
            assert_eq!(key_of(key.as_ref()).len(), good, "{name}");
            let error = generators
                .generate_by_name_with(name, &KeyLength::new(bad))
                .err()
                .unwrap();
            assert_eq!(error.kind(), ErrorKind::InvalidParams, "{name} {bad}");
        }
    }
}
