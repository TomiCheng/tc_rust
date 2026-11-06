use rand_core::CryptoRng;

use crate::{
    AlgoError, DefaultAlgoContext, EntryBase, ErrorKind, KeyGenerator, KeyGeneratorEntry,
    KeyLength, KeyOwned, Params,
};

// The row of a key that is only random bytes, of the length that init gives in a KeyLength. It does
// not guess one, so generate needs init first. Not for algorithms with rules for their keys, such
// as the parity and the weak keys of DES
pub(super) fn key(context: &DefaultAlgoContext) -> Vec<Box<dyn KeyGeneratorEntry>> {
    vec![Box::new(Row {
        rand: context.rand(),
    })]
}

struct Row {
    rand: fn() -> Box<dyn CryptoRng>,
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        "KEY"
    }
}

impl KeyGeneratorEntry for Row {
    fn create(&self) -> Box<dyn KeyGenerator> {
        Box::new(RandomKeyGenerator {
            key_len: None,
            rand: (self.rand)(),
        })
    }
}

struct RandomKeyGenerator {
    key_len: Option<usize>,
    rand: Box<dyn CryptoRng>,
}

impl KeyGenerator for RandomKeyGenerator {
    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError> {
        let bytes = params
            .as_any()
            .downcast_ref::<KeyLength>()
            .map(KeyLength::bytes)
            .filter(|bytes| *bytes > 0)
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        self.key_len = Some(bytes);
        Ok(())
    }

    fn generate(&mut self) -> Result<Box<dyn Params>, AlgoError> {
        let key_len = self
            .key_len
            .ok_or(AlgoError::new(ErrorKind::NotInitialized))?;
        let mut key = vec![0; key_len];
        self.rand.fill_bytes(&mut key);
        Ok(Box::new(KeyOwned::new(key)))
    }
}

#[cfg(test)]
mod tests {
    use core::any::Any;

    use crate::{
        AlgoBuilder, DefaultAlgoBuilder, ErrorKind, KeyGenerator, KeyLength, KeyOwned, KeyParams,
        Params,
    };

    fn generator() -> Box<dyn KeyGenerator> {
        let algo = DefaultAlgoBuilder::default().build();
        algo.key_generator().get_by_name("KEY").unwrap()
    }

    fn key_of(key: &dyn Params) -> Vec<u8> {
        let key = key.as_any().downcast_ref::<KeyOwned>();
        key.expect("a KeyOwned").key().to_vec()
    }

    #[test]
    fn the_key_has_the_length_that_init_gave() {
        for len in [1, 16, 20, 64] {
            let mut generator = generator();
            generator.init(&KeyLength::new(len)).unwrap();
            let key = generator.generate().unwrap();
            assert_eq!(key_of(key.as_ref()).len(), len);
        }
    }

    #[test]
    fn the_helper_with_params_gives_a_key_of_the_length_it_was_given() {
        let algo = DefaultAlgoBuilder::default().build();
        let key = algo
            .key_generator()
            .generate_by_name_with("KEY", &KeyLength::new(32))
            .unwrap();
        assert_eq!(key_of(key.as_ref()).len(), 32);
    }

    #[test]
    fn two_keys_of_one_generator_differ() {
        let mut generator = generator();
        generator.init(&KeyLength::new(32)).unwrap();
        let first = generator.generate().unwrap();
        let second = generator.generate().unwrap();
        assert_ne!(key_of(first.as_ref()), key_of(second.as_ref()));
    }

    #[test]
    fn generate_needs_init_first_so_the_helpers_report_it() {
        let error = generator().generate().err().unwrap();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);

        let algo = DefaultAlgoBuilder::default().build();
        let error = algo.key_generator().generate_by_name("KEY").err().unwrap();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
    }

    struct OtherParams;

    impl Params for OtherParams {
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[test]
    fn init_refuses_no_length_and_params_of_another_type() {
        let mut generator = generator();

        let error = generator.init(&KeyLength::new(0)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);

        let error = generator.init(&OtherParams).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }

    #[cfg(feature = "hmac-sha256")]
    #[test]
    fn a_generated_key_goes_straight_into_a_mac() {
        let algo = DefaultAlgoBuilder::default().build();
        let mut generator = algo.key_generator().get_by_name("KEY").unwrap();
        generator.init(&KeyLength::new(32)).unwrap();
        let key = generator.generate().unwrap();

        let tag = algo
            .mac()
            .calculate_by_name("HMAC-SHA256", key.as_ref(), b"abc")
            .unwrap();
        assert_eq!(tag.len(), 32);
    }
}
