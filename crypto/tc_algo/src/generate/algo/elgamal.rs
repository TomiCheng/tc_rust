use rand_core::CryptoRng;
use tc_asym_cipher::KeyPairGeneratorInit;
use tc_elgamal::{ElGamalKeyGenerationParams, ElGamalKeyPairGenerator, ElGamalParameters};

use crate::generate::{KeyPairGenerator, KeyPairGeneratorEntry};
use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind, Params};

// The row of ElGamal, to give to DefaultAlgoBuilder::reg_key_pair_generator. Its name is that of
// Bouncy Castle's GeneratorUtilities, which gives it no OID
pub(super) fn elgamal(context: &DefaultAlgoContext) -> Vec<Box<dyn KeyPairGeneratorEntry>> {
    vec![Box::new(Row {
        rand: context.rand(),
    })]
}

struct Row {
    rand: fn() -> Box<dyn CryptoRng>,
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        "ELGAMAL"
    }
}

impl KeyPairGeneratorEntry for Row {
    fn create(&self) -> Box<dyn KeyPairGenerator> {
        Box::new(ElGamal {
            rand: (self.rand)(),
            group: None,
        })
    }
}

// Its params are the group, an ElGamalParameters. There is no default group, so generate needs init
struct ElGamal {
    rand: Box<dyn CryptoRng>,
    group: Option<ElGamalParameters>,
}

fn generator<'a>(
    rand: &'a mut dyn CryptoRng,
    group: &ElGamalParameters,
) -> Result<ElGamalKeyPairGenerator<&'a mut dyn CryptoRng>, AlgoError> {
    let mut generator = ElGamalKeyPairGenerator::new(rand);
    generator
        .init(&ElGamalKeyGenerationParams::new(group.clone()))
        .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))?;
    Ok(generator)
}

impl tc_asym_cipher::KeyPairGenerator for ElGamal {
    type PublicKey = Box<dyn Params>;
    type PrivateKey = Box<dyn Params>;
    type Error = AlgoError;

    fn generate_key_pair(&mut self) -> Result<(Box<dyn Params>, Box<dyn Params>), AlgoError> {
        let group = self
            .group
            .as_ref()
            .ok_or(AlgoError::new(ErrorKind::NotInitialized))?;
        let (public, private) = generator(self.rand.as_mut(), group)?
            .generate_key_pair()
            .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))?;
        Ok((Box::new(public), Box::new(private)))
    }
}

impl tc_asym_cipher::KeyPairGeneratorInit<dyn Params> for ElGamal {
    type Error = AlgoError;

    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError> {
        self.group = None;
        let group = params
            .as_any()
            .downcast_ref::<ElGamalParameters>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        // tc_elgamal judges the group when it is initialized, so that a bad one shows here
        generator(self.rand.as_mut(), group)?;
        self.group = Some(group.clone());
        Ok(())
    }
}

impl KeyPairGenerator for ElGamal {}

#[cfg(test)]
mod tests {
    use tc_dh_key::standard_groups::rfc3526_1536;
    use tc_elgamal::{ElGamalParameters, ElGamalPrivateKey, ElGamalPublicKey};

    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind};

    #[test]
    fn a_generated_pair_encrypts_and_decrypts_through_the_cipher_rows() {
        let group = rfc3526_1536();
        let params = ElGamalParameters::new(group.p().clone(), group.g().clone());
        let algo = DefaultAlgoBuilder::default().build();
        let pair = algo
            .key_pair_generator()
            .generate_by_name_with("ElGamal", &params)
            .unwrap();
        assert!(pair.public().as_any().is::<ElGamalPublicKey>());
        assert!(pair.private().as_any().is::<ElGamalPrivateKey>());

        let name = "ELGAMAL//OAEPPADDING";
        let sealed = algo
            .cipher()
            .encrypt_by_name(name, pair.public(), b"attack at dawn")
            .unwrap();
        let opened = algo
            .cipher()
            .decrypt_by_name(name, pair.private(), &sealed)
            .unwrap();
        assert_eq!(opened, b"attack at dawn");
    }

    #[test]
    fn generate_needs_a_group() {
        let algo = DefaultAlgoBuilder::default().build();
        let error = algo
            .key_pair_generator()
            .generate_by_name("ELGAMAL")
            .err()
            .unwrap();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
    }
}
