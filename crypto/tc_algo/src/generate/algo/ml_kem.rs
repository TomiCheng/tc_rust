use rand_core::CryptoRng;
use tc_asym_cipher::{KeyPairGenerator as _, KeyPairGeneratorInit};
use tc_ml_kem::{MlKemKeyGenerationParams, MlKemKeyPairGenerator, MlKemParameters};

use crate::generate::{KeyPair, KeyPairGenerator, KeyPairGeneratorEntry};
use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind, Params};

// The row of ML-KEM, to give to DefaultAlgoBuilder::reg_key_pair_generator. Its name is that of
// Bouncy Castle's GeneratorUtilities, where the parameter set comes with Init
pub(super) fn ml_kem(context: &DefaultAlgoContext) -> Vec<Box<dyn KeyPairGeneratorEntry>> {
    vec![Box::new(Row {
        rand: context.rand(),
    })]
}

struct Row {
    rand: fn() -> Box<dyn CryptoRng>,
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        "ML-KEM"
    }
}

impl KeyPairGeneratorEntry for Row {
    fn create(&self) -> Box<dyn KeyPairGenerator> {
        Box::new(MlKem {
            rand: (self.rand)(),
            params: None,
        })
    }
}

// Its params are the parameter set, an MlKemParameters. There is no default, so generate needs init
struct MlKem {
    rand: Box<dyn CryptoRng>,
    params: Option<MlKemParameters>,
}

impl KeyPairGenerator for MlKem {
    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError> {
        self.params = None;
        let params = params
            .as_any()
            .downcast_ref::<MlKemParameters>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        self.params = Some(*params);
        Ok(())
    }

    fn generate(&mut self) -> Result<KeyPair, AlgoError> {
        let params = self
            .params
            .ok_or(AlgoError::new(ErrorKind::NotInitialized))?;
        let invalid = |error| AlgoError::with_source(ErrorKind::InvalidParams, error);
        let mut generator = MlKemKeyPairGenerator::new();
        generator
            .init(MlKemKeyGenerationParams::new(params, self.rand.as_mut()))
            .map_err(invalid)?;
        let (public, private) = generator.generate_key_pair().map_err(invalid)?;
        Ok(KeyPair::new(Box::new(public), Box::new(private)))
    }
}

#[cfg(test)]
mod tests {
    use tc_ml_kem::{MlKemParameters, MlKemPublicKey};

    use crate::params::KeyLength;
    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind};

    #[test]
    fn the_keys_have_the_parameter_set_given_to_init() {
        let algo = DefaultAlgoBuilder::default().build();
        let params = MlKemParameters::ML_KEM_1024;
        let pair = algo
            .key_pair_generator()
            .generate_by_name_with("ML-KEM", &params)
            .unwrap();
        let public = pair.public().as_any().downcast_ref::<MlKemPublicKey>();
        assert_eq!(public.unwrap().params(), params);
    }

    #[test]
    fn generate_needs_an_init_that_succeeded() {
        let algo = DefaultAlgoBuilder::default().build();
        let generators = algo.key_pair_generator();
        let error = generators.generate_by_name("ML-KEM").err().unwrap();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);

        let mut generator = generators.get_by_name("ML-KEM").unwrap();
        generator.init(&MlKemParameters::ML_KEM_768).unwrap();
        let error = generator.init(&KeyLength::new(1)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
        let error = generator.generate().err().unwrap();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
    }
}
