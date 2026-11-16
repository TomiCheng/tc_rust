use rand_core::CryptoRng;
use tc_asn1::Asn1Oid;

use crate::generate::{KeyGenerator, KeyGeneratorEntry};
use crate::params::KeyOwned;
use crate::{AlgoError, DefaultAlgoContext, EntryBase, Params};

// The rows of the keys of the block ciphers but AES128, AES192 and AES256, to give to
// DefaultAlgoBuilder::reg_key_generator. Their names, aliases, OIDs and key lengths are those of
// Bouncy Castle's GeneratorUtilities, with DESEDE16 and DESEDE24 besides for the two lengths of
// DESede. Each is behind the feature of its cipher
pub(super) fn block(context: &DefaultAlgoContext) -> Vec<Box<dyn KeyGeneratorEntry>> {
    let rand = context.rand();
    let mut rows: Vec<Box<dyn KeyGeneratorEntry>> = Vec::new();
    let mut add = |name, aliases: &[&'static str], oids: &[&str], key_len, rule| {
        rows.push(row(name, aliases, oids, key_len, rule, rand));
    };
    #[cfg(feature = "aes")]
    add("AES", &["AESWRAP"], &[], 24, Rule::Random);
    // CBC, CCM, CFB, CTR, ECB, GCM, KW, KWP, OCB2 and OFB of NSRI
    #[cfg(feature = "aria")]
    {
        add("ARIA", &[], &[], 32, Rule::Random);
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
            Rule::Random,
        );
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
            Rule::Random,
        );
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
            Rule::Random,
        );
    }
    #[cfg(feature = "blowfish")]
    add(
        "BLOWFISH",
        &[],
        &["1.3.6.1.4.1.3029.1.2", "1.3.6.1.4.1.3029.1.1.2"],
        16,
        Rule::Random,
    );
    #[cfg(feature = "camellia")]
    {
        add("CAMELLIA", &["CAMELLIAWRAP"], &[], 32, Rule::Random);
        for (name, arc, key_len) in [
            ("CAMELLIA128", 2, 16),
            ("CAMELLIA192", 3, 24),
            ("CAMELLIA256", 4, 32),
        ] {
            let oids = [
                format!("1.2.392.200011.61.1.1.1.{arc}"),
                format!("1.2.392.200011.61.1.1.3.{arc}"),
            ];
            add(name, &[], &[&oids[0], &oids[1]], key_len, Rule::Random);
        }
    }
    #[cfg(feature = "cast5")]
    add("CAST5", &[], &["1.2.840.113533.7.66.10"], 16, Rule::Random);
    #[cfg(feature = "cast6")]
    add("CAST6", &[], &[], 32, Rule::Random);
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
        Rule::Des,
    );
    #[cfg(feature = "desede")]
    {
        add(
            "DESEDE",
            &["DESEDEWRAP", "TDEA", "DESEDE16"],
            &["1.3.14.3.2.17"],
            16,
            Rule::DesEde,
        );
        add(
            "DESEDE3",
            &["DESEDE24"],
            &["1.2.840.113549.3.7", "1.2.840.113549.1.9.16.3.6"],
            24,
            Rule::DesEde,
        );
    }
    #[cfg(feature = "gost28147")]
    add(
        "GOST28147",
        &["GOST", "GOST-28147"],
        &["1.2.643.2.2.21"],
        32,
        Rule::Random,
    );
    #[cfg(feature = "idea")]
    add("IDEA", &[], &["1.3.6.1.4.1.188.7.1.1.2"], 16, Rule::Random);
    #[cfg(feature = "noekeon")]
    add("NOEKEON", &[], &[], 16, Rule::Random);
    #[cfg(feature = "rc2")]
    add(
        "RC2",
        &[],
        &["1.2.840.113549.3.2", "1.2.840.113549.1.9.16.3.7"],
        16,
        Rule::Random,
    );
    #[cfg(feature = "rc5")]
    add("RC5", &["RC5-32"], &[], 16, Rule::Random);
    #[cfg(feature = "rc5-64")]
    add("RC5-64", &[], &[], 32, Rule::Random);
    #[cfg(feature = "rc6")]
    add("RC6", &[], &[], 32, Rule::Random);
    #[cfg(feature = "rijndael")]
    add("RIJNDAEL", &[], &[], 24, Rule::Random);
    #[cfg(feature = "seed")]
    add(
        "SEED",
        &[],
        &["1.2.410.200004.7.1.1.1", "1.2.410.200004.1.4"],
        16,
        Rule::Random,
    );
    #[cfg(feature = "serpent")]
    add("SERPENT", &[], &[], 24, Rule::Random);
    #[cfg(feature = "skipjack")]
    add("SKIPJACK", &[], &[], 10, Rule::Random);
    #[cfg(feature = "sm4")]
    add("SM4", &[], &[], 16, Rule::Random);
    #[cfg(feature = "tea")]
    add("TEA", &[], &[], 16, Rule::Random);
    #[cfg(feature = "threefish-256")]
    add("THREEFISH-256", &[], &[], 32, Rule::Random);
    #[cfg(feature = "threefish-512")]
    add("THREEFISH-512", &[], &[], 64, Rule::Random);
    #[cfg(feature = "threefish-1024")]
    add("THREEFISH-1024", &[], &[], 128, Rule::Random);
    #[cfg(feature = "tnepres")]
    add("TNEPRES", &[], &[], 24, Rule::Random);
    #[cfg(feature = "twofish")]
    add("TWOFISH", &[], &[], 32, Rule::Random);
    #[cfg(feature = "xtea")]
    add("XTEA", &[], &[], 16, Rule::Random);
    rows
}

// What a key must keep to besides being random: DES and DESede, as Bouncy Castle's DesKeyGenerator
// and DesEdeKeyGenerator, set the parity bits and draw again for a weak key, and for DESede again
// for a key whose parts repeat, which is DES in disguise
#[derive(Clone, Copy)]
enum Rule {
    #[allow(dead_code, reason = "unused when only DES or DESede is on")]
    Random,
    #[cfg(feature = "des")]
    Des,
    #[cfg(feature = "desede")]
    DesEde,
}

fn row(
    name: &'static str,
    aliases: &[&'static str],
    oids: &[&str],
    key_len: usize,
    rule: Rule,
    rand: fn() -> Box<dyn CryptoRng>,
) -> Box<dyn KeyGeneratorEntry> {
    Box::new(Row {
        name,
        aliases: aliases.iter().map(|alias| alias.to_string()).collect(),
        oids: oids
            .iter()
            .map(|dotted| dotted.parse().expect("a valid OID"))
            .collect(),
        key_len,
        rule,
        rand,
    })
}

struct Row {
    name: &'static str,
    aliases: Vec<String>,
    oids: Vec<Asn1Oid>,
    key_len: usize,
    rule: Rule,
    rand: fn() -> Box<dyn CryptoRng>,
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        self.name
    }

    fn aliases(&self) -> &[String] {
        &self.aliases
    }

    fn oids(&self) -> &[Asn1Oid] {
        &self.oids
    }
}

impl KeyGeneratorEntry for Row {
    fn create(&self) -> Box<dyn KeyGenerator> {
        Box::new(FixedKeyGenerator {
            key_len: self.key_len,
            rule: self.rule,
            rand: (self.rand)(),
        })
    }
}

// A key of the row's length, with no params to set
struct FixedKeyGenerator {
    key_len: usize,
    rule: Rule,
    rand: Box<dyn CryptoRng>,
}

impl KeyGenerator for FixedKeyGenerator {
    fn generate(&mut self) -> Result<Box<dyn Params>, AlgoError> {
        let mut key = vec![0; self.key_len];
        loop {
            self.rand.fill_bytes(&mut key);
            let done = match self.rule {
                Rule::Random => true,
                #[cfg(feature = "des")]
                Rule::Des => {
                    tc_des::set_odd_parity(&mut key);
                    !tc_des::is_weak_key(key.as_slice().try_into().expect("8 bytes"))
                }
                #[cfg(feature = "desede")]
                Rule::DesEde => {
                    tc_des::set_odd_parity(&mut key);
                    !tc_des::is_weak_ede_key(&key) && tc_des::is_real_ede_key(&key)
                }
            };
            if done {
                return Ok(Box::new(KeyOwned::new(key)));
            }
        }
    }
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
            ("GOST28147", 32),
            ("GOST", 32),
            ("IDEA", 16),
            ("NOEKEON", 16),
            ("RC2", 16),
            ("RC5", 16),
            ("RC5-32", 16),
            ("RC5-64", 32),
            ("RC6", 32),
            ("RIJNDAEL", 24),
            ("SEED", 16),
            ("SERPENT", 24),
            ("SKIPJACK", 10),
            ("SM4", 16),
            ("TEA", 16),
            ("THREEFISH-256", 32),
            ("THREEFISH-512", 64),
            ("THREEFISH-1024", 128),
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
}
