use super::fixed::{Lengths, row};
use super::random::Rule;
use crate::DefaultAlgoContext;
use crate::generate::KeyGeneratorEntry;

// The rows of the keys of the AEAD ciphers that are algorithms of their own, to give to
// DefaultAlgoBuilder::reg_key_generator. Bouncy Castle's GeneratorUtilities names none of them, so
// the names are those of their cipher rows, with the length of each key. The AEAD modes of a block
// cipher take the key of the cipher, and ChaCha20-Poly1305 and XChaCha20-Poly1305 those of
// ChaCha7539 and XChaCha20, which have rows of their own. Each is behind the feature of its cipher
pub(super) fn aead(context: &DefaultAlgoContext) -> Vec<Box<dyn KeyGeneratorEntry>> {
    let rand = context.rand();
    let mut rows: Vec<Box<dyn KeyGeneratorEntry>> = Vec::new();
    let mut add = |name, aliases: &[&'static str], oids: &[&str], key_len, lengths, rule| {
        rows.push(row(name, aliases, oids, key_len, lengths, rule, rand));
    };
    #[cfg(feature = "ascon-aead")]
    add(
        "ASCON-AEAD128",
        &[],
        &[],
        16,
        Lengths::Of(&[16]),
        Rule::Random,
    );
    #[cfg(feature = "ascon-aead")]
    add("ASCON-128", &[], &[], 16, Lengths::Of(&[16]), Rule::Random);
    #[cfg(feature = "ascon-aead")]
    add("ASCON-128A", &[], &[], 16, Lengths::Of(&[16]), Rule::Random);
    #[cfg(feature = "ascon-aead")]
    add("ASCON-80PQ", &[], &[], 20, Lengths::Of(&[20]), Rule::Random);
    #[cfg(feature = "grain128-aead")]
    add(
        "GRAIN-128AEAD",
        &[],
        &[],
        16,
        Lengths::Of(&[16]),
        Rule::Random,
    );
    #[cfg(feature = "sparkle-aead")]
    add(
        "SCHWAEMM128-128",
        &[],
        &[],
        16,
        Lengths::Of(&[16]),
        Rule::Random,
    );
    #[cfg(feature = "sparkle-aead")]
    add(
        "SCHWAEMM256-128",
        &[],
        &[],
        16,
        Lengths::Of(&[16]),
        Rule::Random,
    );
    #[cfg(feature = "sparkle-aead")]
    add(
        "SCHWAEMM192-192",
        &[],
        &[],
        24,
        Lengths::Of(&[24]),
        Rule::Random,
    );
    #[cfg(feature = "sparkle-aead")]
    add(
        "SCHWAEMM256-256",
        &[],
        &[],
        32,
        Lengths::Of(&[32]),
        Rule::Random,
    );
    rows
}

#[cfg(test)]
mod tests {
    use crate::params::{AeadParamsOwned, KeyOwned, KeyParams};
    use crate::{AlgoBuilder, DefaultAlgoBuilder};

    // Each row gives a key of its cipher's length, which the cipher takes as it is
    #[test]
    fn every_row_gives_the_key_of_its_cipher() {
        let algo = DefaultAlgoBuilder::default().build();
        for (name, key_bytes, nonce_bytes, tag_bytes) in [
            ("ASCON-AEAD128", 16, 16, 16),
            ("ASCON-128", 16, 16, 16),
            ("ASCON-128A", 16, 16, 16),
            ("ASCON-80PQ", 20, 16, 16),
            ("GRAIN-128AEAD", 16, 12, 8),
            ("SCHWAEMM128-128", 16, 16, 16),
            ("SCHWAEMM256-128", 16, 32, 16),
            ("SCHWAEMM192-192", 24, 24, 24),
            ("SCHWAEMM256-256", 32, 32, 32),
        ] {
            let key = algo.key_generator().generate_by_name(name).unwrap();
            let key = key
                .as_any()
                .downcast_ref::<KeyOwned>()
                .unwrap()
                .key()
                .to_vec();
            assert_eq!(key.len(), key_bytes, "{name}");

            let params = AeadParamsOwned::new(key, vec![0x24; nonce_bytes], tag_bytes, Vec::new());
            let sealed = algo
                .cipher()
                .encrypt_by_name(name, &params, b"attack at dawn")
                .unwrap();
            let opened = algo
                .cipher()
                .decrypt_by_name(name, &params, &sealed)
                .unwrap();
            assert_eq!(opened, b"attack at dawn", "{name}");
        }
    }
}
