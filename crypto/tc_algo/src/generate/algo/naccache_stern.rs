use rand_core::CryptoRng;
use tc_asym_cipher::KeyPairGeneratorInit;
use tc_naccache_stern::{NaccacheSternKeyGenerationParams, NaccacheSternKeyPairGenerator};

use crate::generate::{KeyPairGenerator, KeyPairGeneratorEntry};
use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind, Params};

// The row of Naccache-Stern, to give to DefaultAlgoBuilder::reg_key_pair_generator. Bouncy Castle
// has the generator but no name for it in GeneratorUtilities, so the name is that of the cipher row
pub(super) fn naccache_stern(context: &DefaultAlgoContext) -> Vec<Box<dyn KeyPairGeneratorEntry>> {
    vec![Box::new(Row {
        rand: context.rand(),
    })]
}

struct Row {
    rand: fn() -> Box<dyn CryptoRng>,
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        "NACCACHESTERN"
    }
}

impl KeyPairGeneratorEntry for Row {
    fn create(&self) -> Box<dyn KeyPairGenerator> {
        Box::new(NaccacheStern {
            rand: (self.rand)(),
            params: None,
        })
    }
}

// Its params are a NaccacheSternKeyGenerationParams: the size of n, the certainty of the prime tests
// and the count of small primes. There is no default, so generate needs init
struct NaccacheStern {
    rand: Box<dyn CryptoRng>,
    params: Option<NaccacheSternKeyGenerationParams>,
}

fn generator<'a>(
    rand: &'a mut dyn CryptoRng,
    params: &NaccacheSternKeyGenerationParams,
) -> Result<NaccacheSternKeyPairGenerator<&'a mut dyn CryptoRng>, AlgoError> {
    let mut generator = NaccacheSternKeyPairGenerator::new(rand);
    generator
        .init(params)
        .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))?;
    Ok(generator)
}

impl tc_asym_cipher::KeyPairGenerator for NaccacheStern {
    type PublicKey = Box<dyn Params>;
    type PrivateKey = Box<dyn Params>;
    type Error = AlgoError;

    fn generate_key_pair(&mut self) -> Result<(Box<dyn Params>, Box<dyn Params>), AlgoError> {
        let params = self
            .params
            .as_ref()
            .ok_or(AlgoError::new(ErrorKind::NotInitialized))?;
        let (public, private) = generator(self.rand.as_mut(), params)?
            .generate_key_pair()
            .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))?;
        Ok((Box::new(public), Box::new(private)))
    }
}

impl tc_asym_cipher::KeyPairGeneratorInit<dyn Params> for NaccacheStern {
    type Error = AlgoError;

    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError> {
        self.params = None;
        let params = params
            .as_any()
            .downcast_ref::<NaccacheSternKeyGenerationParams>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        // tc_naccache_stern judges the values when it is initialized, so that a bad one shows here
        generator(self.rand.as_mut(), params)?;
        self.params = Some(*params);
        Ok(())
    }
}

impl KeyPairGenerator for NaccacheStern {}

#[cfg(test)]
mod tests {
    use tc_naccache_stern::{
        NaccacheSternKeyGenerationParams, NaccacheSternPrivateKey, NaccacheSternPublicKey,
    };

    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind};

    // The 768-bit key of 30 small primes of Bouncy Castle's tests; its messages are below the
    // product of the primes, so a short one, which decrypts to a number as long as the block
    #[test]
    fn a_generated_pair_encrypts_and_decrypts_through_the_cipher_row() {
        let algo = DefaultAlgoBuilder::default().build();
        let pair = algo
            .key_pair_generator()
            .generate_by_name_with(
                "NaccacheStern",
                &NaccacheSternKeyGenerationParams::new(768, 8, 30),
            )
            .unwrap();
        assert!(pair.public().as_any().is::<NaccacheSternPublicKey>());
        assert!(pair.private().as_any().is::<NaccacheSternPrivateKey>());

        let message = [0x01, 0x23];
        let sealed = algo
            .cipher()
            .encrypt_by_name("NACCACHESTERN", pair.public(), &message)
            .unwrap();
        let opened = algo
            .cipher()
            .decrypt_by_name("NACCACHESTERN//NOPADDING", pair.private(), &sealed)
            .unwrap();
        assert!(opened.ends_with(&message));
    }

    #[test]
    fn generate_needs_params_and_init_refuses_bad_ones() {
        let algo = DefaultAlgoBuilder::default().build();
        let generators = algo.key_pair_generator();
        let error = generators.generate_by_name("NACCACHESTERN").err().unwrap();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);

        let error = generators
            .generate_by_name_with(
                "NACCACHESTERN",
                &NaccacheSternKeyGenerationParams::new(200, 8, 30),
            )
            .err()
            .unwrap();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}
