use rand_core::CryptoRng;
use tc_asn1::Asn1Oid;

use crate::{
    AlgoError, DefaultAlgoContext, EntryBase, KeyGenerator, KeyGeneratorEntry, KeyOwned, Params,
};

// The rows of AES, to give to DefaultAlgoBuilder::reg_key_generator. Their names and OIDs are those
// of Bouncy Castle's GeneratorUtilities, without its aliases for the OIDs it calls wrong. An OID
// says the length of the key, so that a row can be found by the OID of the cipher it is for
pub(super) fn aes(context: &DefaultAlgoContext) -> Vec<Box<dyn KeyGeneratorEntry>> {
    let rand = context.rand();
    vec![
        row("AES128", 16, 0, rand),
        row("AES192", 24, 20, rand),
        row("AES256", 32, 40, rand),
    ]
}

// NIST numbers the eight modes of each key length alike, 20 arcs apart
fn row(
    name: &'static str,
    key_len: usize,
    arc_offset: u32,
    rand: fn() -> Box<dyn CryptoRng>,
) -> Box<dyn KeyGeneratorEntry> {
    Box::new(Row {
        name,
        key_len,
        oids: (1..=8)
            .map(|arc| oid(&format!("2.16.840.1.101.3.4.1.{}", arc + arc_offset)))
            .collect(),
        rand,
    })
}

fn oid(dotted: &str) -> Asn1Oid {
    dotted.parse().expect("a valid OID")
}

struct Row {
    name: &'static str,
    key_len: usize,
    oids: Vec<Asn1Oid>,
    rand: fn() -> Box<dyn CryptoRng>,
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        self.name
    }

    fn oids(&self) -> &[Asn1Oid] {
        &self.oids
    }
}

impl KeyGeneratorEntry for Row {
    fn create(&self) -> Box<dyn KeyGenerator> {
        Box::new(AesKeyGenerator {
            key_len: self.key_len,
            rand: (self.rand)(),
        })
    }
}

struct AesKeyGenerator {
    key_len: usize,
    rand: Box<dyn CryptoRng>,
}

impl KeyGenerator for AesKeyGenerator {
    fn generate(&mut self) -> Result<Box<dyn Params>, AlgoError> {
        let mut key = vec![0; self.key_len];
        self.rand.fill_bytes(&mut key);
        Ok(Box::new(KeyOwned::new(key)))
    }
}

#[cfg(test)]
mod tests {
    use core::any::Any;
    use core::convert::Infallible;

    use rand_core::{CryptoRng, TryCryptoRng, TryRng};
    use tc_asn1::Asn1Oid;

    use crate::{
        AlgoBuilder, DefaultAlgoBuilder, ErrorKind, KeyGenerator, KeyOwned, KeyParams, Params,
    };

    fn key_of(key: &dyn Params) -> Vec<u8> {
        let key = key.as_any().downcast_ref::<KeyOwned>();
        key.expect("a KeyOwned").key().to_vec()
    }

    fn oid(dotted: &str) -> Asn1Oid {
        dotted.parse().expect("a valid OID")
    }

    #[test]
    fn each_row_gives_a_key_of_its_length() {
        let algo = DefaultAlgoBuilder::default().build();
        for (name, len) in [("AES128", 16), ("AES192", 24), ("AES256", 32)] {
            let key = algo.key_generator().generate_by_name(name).unwrap();
            assert_eq!(key_of(key.as_ref()).len(), len);
        }
    }

    #[test]
    fn an_oid_gives_a_key_of_the_length_it_says() {
        let algo = DefaultAlgoBuilder::default().build();
        for (dotted, len) in [
            ("2.16.840.1.101.3.4.1.2", 16),
            ("2.16.840.1.101.3.4.1.8", 16),
            ("2.16.840.1.101.3.4.1.22", 24),
            ("2.16.840.1.101.3.4.1.42", 32),
            ("2.16.840.1.101.3.4.1.48", 32),
        ] {
            let key = algo.key_generator().generate_by_oid(&oid(dotted)).unwrap();
            assert_eq!(key_of(key.as_ref()).len(), len);
        }
    }

    #[test]
    fn two_keys_of_one_generator_differ() {
        let algo = DefaultAlgoBuilder::default().build();
        let mut generator = algo.key_generator().get_by_name("AES256").unwrap();
        let first = generator.generate().unwrap();
        let second = generator.generate().unwrap();
        assert_ne!(key_of(first.as_ref()), key_of(second.as_ref()));
    }

    #[test]
    fn a_generated_key_goes_straight_into_a_cipher() {
        let algo = DefaultAlgoBuilder::default().build();
        let key = algo.key_generator().generate_by_name("AES128").unwrap();
        let key = key.as_ref();
        let name = "AES/ECB/PKCS7PADDING";

        let encrypted = algo.cipher().encrypt_by_name(name, key, b"abc").unwrap();
        let decrypted = algo
            .cipher()
            .decrypt_by_name(name, key, &encrypted)
            .unwrap();
        assert_eq!(decrypted, b"abc");
    }

    struct Sevens;

    impl TryRng for Sevens {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Infallible> {
            Ok(0x0707_0707)
        }

        fn try_next_u64(&mut self) -> Result<u64, Infallible> {
            Ok(0x0707_0707_0707_0707)
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
            dst.fill(7);
            Ok(())
        }
    }

    impl TryCryptoRng for Sevens {}

    fn sevens() -> Box<dyn CryptoRng> {
        Box::new(Sevens)
    }

    #[test]
    fn the_key_comes_from_the_rand_set_on_the_builder() {
        let mut builder = DefaultAlgoBuilder::default();
        builder.set_rand(sevens);
        let algo = builder.build();

        let key = algo.key_generator().generate_by_name("AES128").unwrap();
        assert_eq!(key_of(key.as_ref()), [7; 16]);
    }

    struct OtherParams;

    impl Params for OtherParams {
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[test]
    fn a_row_has_nothing_to_set_so_init_refuses_any_params() {
        let algo = DefaultAlgoBuilder::default().build();
        let mut generator: Box<dyn KeyGenerator> =
            algo.key_generator().get_by_name("AES128").unwrap();

        let error = generator.init(&OtherParams).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}
