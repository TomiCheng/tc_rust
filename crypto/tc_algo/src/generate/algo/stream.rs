use super::fixed::{Lengths, row};
use super::random::Rule;
use crate::DefaultAlgoContext;
use crate::generate::KeyGeneratorEntry;

// The rows of the keys of the stream ciphers, to give to DefaultAlgoBuilder::reg_key_generator.
// Their names, aliases, OIDs and key lengths are those of Bouncy Castle's GeneratorUtilities, with
// XSALSA20 besides, which it has as an engine but not there; ChaCha20-Poly1305 and
// XChaCha20-Poly1305 take the keys of ChaCha7539 and XChaCha20, as there. ISAAC, which takes a key
// of any length, has no row: KEY gives one. Each is behind the feature of its cipher
pub(super) fn stream(context: &DefaultAlgoContext) -> Vec<Box<dyn KeyGeneratorEntry>> {
    let rand = context.rand();
    let mut rows: Vec<Box<dyn KeyGeneratorEntry>> = Vec::new();
    let mut add = |name, aliases: &[&'static str], oids: &[&str], key_len, lengths, rule| {
        rows.push(row(name, aliases, oids, key_len, lengths, rule, rand));
    };
    #[cfg(feature = "chacha")]
    add("CHACHA", &[], &[], 16, Lengths::Of(&[16, 32]), Rule::Random);
    #[cfg(any(feature = "chacha", feature = "chacha-aead"))]
    add(
        "CHACHA7539",
        &["CHACHA20", "CHACHA20-POLY1305"],
        &["1.2.840.113549.1.9.16.3.18"],
        32,
        Lengths::Of(&[32]),
        Rule::Random,
    );
    #[cfg(any(feature = "chacha", feature = "chacha-aead"))]
    add(
        "XCHACHA20",
        &["XCHACHA20-POLY1305"],
        &[],
        32,
        Lengths::Of(&[32]),
        Rule::Random,
    );
    #[cfg(feature = "hc")]
    add("HC128", &[], &[], 16, Lengths::Of(&[16]), Rule::Random);
    #[cfg(feature = "hc")]
    add("HC256", &[], &[], 32, Lengths::Of(&[16, 32]), Rule::Random);
    #[cfg(feature = "rc4-family")]
    add(
        "RC4",
        &["ARC4"],
        &["1.2.840.113549.3.4"],
        16,
        Lengths::range(1, 256),
        Rule::Random,
    );
    #[cfg(feature = "salsa20")]
    add(
        "SALSA20",
        &[],
        &[],
        16,
        Lengths::Of(&[16, 32]),
        Rule::Random,
    );
    #[cfg(feature = "salsa20")]
    add("XSALSA20", &[], &[], 32, Lengths::Of(&[32]), Rule::Random);
    #[cfg(feature = "rc4-family")]
    add("VMPC", &[], &[], 16, Lengths::range(16, 64), Rule::Random);
    #[cfg(feature = "rc4-family")]
    add(
        "VMPC-KSA3",
        &[],
        &[],
        16,
        Lengths::range(16, 64),
        Rule::Random,
    );
    rows
}

#[cfg(test)]
mod tests {
    use crate::params::{KeyOwned, KeyParams, KeyWithIvOwned};
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
            ("CHACHA", 16),
            ("CHACHA7539", 32),
            ("CHACHA20", 32),
            ("CHACHA20-POLY1305", 32),
            ("XCHACHA20", 32),
            ("XCHACHA20-POLY1305", 32),
            ("HC128", 16),
            ("HC256", 32),
            ("RC4", 16),
            ("ARC4", 16),
            ("SALSA20", 16),
            ("XSALSA20", 32),
            ("VMPC", 16),
            ("VMPC-KSA3", 16),
        ] {
            let key = generators.generate_by_name(name).unwrap();
            assert_eq!(key_of(key.as_ref()).len(), bytes, "{name}");
        }
        let key = generators
            .generate_by_oid(&"1.2.840.113549.1.9.16.3.18".parse().unwrap())
            .unwrap();
        assert_eq!(key_of(key.as_ref()).len(), 32);
    }

    // A generated key goes straight into its cipher
    #[test]
    fn a_generated_key_goes_into_its_cipher() {
        let algo = DefaultAlgoBuilder::default().build();
        let key = algo.key_generator().generate_by_name("CHACHA20").unwrap();
        let params = KeyWithIvOwned::new(key_of(key.as_ref()), vec![0x24; 12]);
        let sealed = algo
            .cipher()
            .encrypt_by_name("CHACHA7539", &params, b"attack at dawn")
            .unwrap();
        let opened = algo
            .cipher()
            .decrypt_by_name("CHACHA7539", &params, &sealed)
            .unwrap();
        assert_eq!(opened, b"attack at dawn");
    }

    // Without init a row gives its default length; init sets another the cipher takes, and a
    // length it does not take is InvalidParams, which keeps the length before
    #[test]
    fn init_sets_a_length_the_cipher_takes() {
        use crate::params::KeyLength;

        let algo = DefaultAlgoBuilder::default().build();
        let mut generator = algo.key_generator().get_by_name("VMPC").unwrap();
        assert_eq!(key_of(generator.generate().unwrap().as_ref()).len(), 16);

        generator.init(&KeyLength::new(64)).unwrap();
        assert_eq!(key_of(generator.generate().unwrap().as_ref()).len(), 64);

        for bytes in [8, 65] {
            let error = generator.init(&KeyLength::new(bytes)).unwrap_err();
            assert_eq!(error.kind(), crate::ErrorKind::InvalidParams, "{bytes}");
        }
        assert_eq!(key_of(generator.generate().unwrap().as_ref()).len(), 64);
    }
}
