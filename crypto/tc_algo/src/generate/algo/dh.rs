use rand_core::CryptoRng;
use tc_asym_cipher::KeyPairGeneratorInit;
use tc_dh_key::{DhKeyGenerationParams, DhKeyPairGenerator, DhParameters};

use crate::generate::{KeyPairGenerator, KeyPairGeneratorEntry};
use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind, Params};

// The row of DH, to give to DefaultAlgoBuilder::reg_key_pair_generator. Its name and alias are those
// of Bouncy Castle's GeneratorUtilities, which gives it no OID
pub(super) fn dh(context: &DefaultAlgoContext) -> Vec<Box<dyn KeyPairGeneratorEntry>> {
    vec![Box::new(Row {
        aliases: vec!["DIFFIEHELLMAN".to_string()],
        rand: context.rand(),
    })]
}

struct Row {
    aliases: Vec<String>,
    rand: fn() -> Box<dyn CryptoRng>,
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        "DH"
    }

    fn aliases(&self) -> &[String] {
        &self.aliases
    }
}

impl KeyPairGeneratorEntry for Row {
    fn create(&self) -> Box<dyn KeyPairGenerator> {
        Box::new(Dh {
            rand: (self.rand)(),
            group: None,
        })
    }
}

// Its params are the group, a DhParameters. There is no default group, so generate needs init
struct Dh {
    rand: Box<dyn CryptoRng>,
    group: Option<DhParameters>,
}

fn generator<'a>(
    rand: &'a mut dyn CryptoRng,
    group: &DhParameters,
) -> Result<DhKeyPairGenerator<'a>, AlgoError> {
    let mut generator = DhKeyPairGenerator::new();
    generator
        .init(DhKeyGenerationParams::new(group.clone(), rand))
        .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))?;
    Ok(generator)
}

impl tc_asym_cipher::KeyPairGenerator for Dh {
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

impl<'a> tc_asym_cipher::KeyPairGeneratorInit<&'a dyn Params> for Dh {
    type Error = AlgoError;

    fn init(&mut self, params: &'a dyn Params) -> Result<(), AlgoError> {
        self.group = None;
        let group = params
            .as_any()
            .downcast_ref::<DhParameters>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        // tc_dh_key judges the group when it is initialized, so that a bad one shows here
        generator(self.rand.as_mut(), group)?;
        self.group = Some(group.clone());
        Ok(())
    }
}

impl KeyPairGenerator for Dh {}

#[cfg(test)]
mod tests {
    use tc_bigint::PaddedBigUint;
    use tc_dh_key::{DhParameters, DhPrivateKey, DhPublicKey};

    use crate::params::KeyLength;
    use crate::params::dh_groups::{rfc3526_2048, rfc3526_3072};
    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind};

    const NAME: &str = "DH";

    #[test]
    fn the_helper_generates_a_public_and_a_private_key_of_the_group() {
        let algo = DefaultAlgoBuilder::default().build();
        let group = rfc3526_3072();
        let pair = algo
            .key_pair_generator()
            .generate_by_name_with(NAME, &group)
            .unwrap();

        let public = pair.public().as_any().downcast_ref::<DhPublicKey>();
        assert_eq!(public.expect("a DhPublicKey").params(), &group);
        let private = pair.private().as_any().downcast_ref::<DhPrivateKey>();
        assert_eq!(private.expect("a DhPrivateKey").params(), &group);
    }

    #[test]
    fn a_generator_gives_a_new_pair_each_time() {
        let algo = DefaultAlgoBuilder::default().build();
        let mut generator = algo.key_pair_generator().get_by_name(NAME).unwrap();
        generator.init(&rfc3526_2048()).unwrap();

        let first = generator.generate().unwrap();
        let second = generator.generate().unwrap();
        let y = |pair: &crate::generate::KeyPair| {
            let public = pair.public().as_any().downcast_ref::<DhPublicKey>();
            public.expect("a DhPublicKey").y().clone()
        };
        assert_ne!(y(&first), y(&second));
    }

    #[test]
    fn two_generated_pairs_reach_one_secret_through_the_agreement_row() {
        let algo = DefaultAlgoBuilder::default().build();
        let group = rfc3526_2048();
        let generators = algo.key_pair_generator();
        let alice = generators.generate_by_name_with(NAME, &group).unwrap();
        let bob = generators.generate_by_name_with(NAME, &group).unwrap();

        let mut agreement = algo.agreement().get_by_name(NAME).unwrap();
        agreement.init(alice.private()).unwrap();
        let alice_secret = agreement.calculate_shared_secret(bob.public()).unwrap();
        agreement.init(bob.private()).unwrap();
        let bob_secret = agreement.calculate_shared_secret(alice.public()).unwrap();

        assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
    }

    #[test]
    fn the_row_is_found_by_its_alias_whatever_the_case() {
        let algo = DefaultAlgoBuilder::default().build();
        assert!(
            algo.key_pair_generator()
                .get_by_name("DiffieHellman")
                .is_ok()
        );
        assert!(algo.key_pair_generator().get_by_name("dh").is_ok());
    }

    #[test]
    fn generate_needs_an_init_that_succeeded() {
        let algo = DefaultAlgoBuilder::default().build();
        let error = algo
            .key_pair_generator()
            .generate_by_name(NAME)
            .err()
            .unwrap();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);

        let mut generator = algo.key_pair_generator().get_by_name(NAME).unwrap();
        generator.init(&rfc3526_2048()).unwrap();
        assert!(generator.init(&KeyLength::new(1)).is_err());
        let error = generator.generate().err().unwrap();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
    }

    #[test]
    fn init_refuses_params_of_another_type_or_a_bad_group() {
        let algo = DefaultAlgoBuilder::default().build();
        let mut generator = algo.key_pair_generator().get_by_name(NAME).unwrap();
        let error = generator.init(&KeyLength::new(1)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);

        let even_p = DhParameters::new(PaddedBigUint::from(4u8), PaddedBigUint::from(2u8));
        let error = generator.init(&even_p).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}
