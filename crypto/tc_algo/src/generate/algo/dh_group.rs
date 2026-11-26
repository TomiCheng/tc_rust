use rand_core::CryptoRng;
use tc_dh_key::{DhGroupGenerationParams, DhGroupGenerator};

use crate::generate::{ParamsGenerator, ParamsGeneratorEntry};
use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind, Params};

// The row of DH_GROUP, to give to DefaultAlgoBuilder::reg_params_generator: a new group of Bouncy
// Castle's DHParametersGenerator, a DhParameters for the DH key pair generator
pub(super) fn dh_group(context: &DefaultAlgoContext) -> Vec<Box<dyn ParamsGeneratorEntry>> {
    vec![Box::new(Row {
        rand: context.rand(),
    })]
}

struct Row {
    rand: fn() -> Box<dyn CryptoRng>,
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        "DH_GROUP"
    }
}

impl ParamsGeneratorEntry for Row {
    fn create(&self) -> Box<dyn ParamsGenerator> {
        Box::new(DhGroup {
            rand: (self.rand)(),
            params: DhGroupGenerationParams::new(),
        })
    }
}

// Its params are a DhGroupGenerationParams; without init, those of DhGroupGenerationParams::new
struct DhGroup {
    rand: Box<dyn CryptoRng>,
    params: DhGroupGenerationParams,
}

fn generator<'a>(
    rand: &'a mut dyn CryptoRng,
    params: &DhGroupGenerationParams,
) -> Result<DhGroupGenerator<&'a mut dyn CryptoRng>, AlgoError> {
    let mut generator = DhGroupGenerator::new(rand);
    generator
        .init(params)
        .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))?;
    Ok(generator)
}

impl ParamsGenerator for DhGroup {
    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError> {
        let params = params
            .as_any()
            .downcast_ref::<DhGroupGenerationParams>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        // tc_dh_key judges the params when it is initialized, so that bad ones show here
        generator(self.rand.as_mut(), params)?;
        self.params = *params;
        Ok(())
    }

    fn generate(&mut self) -> Result<Box<dyn Params>, AlgoError> {
        let group = generator(self.rand.as_mut(), &self.params)?
            .generate_group()
            .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))?;
        Ok(Box::new(group))
    }
}

#[cfg(test)]
mod tests {
    use tc_dh_key::{DhGroupGenerationParams, DhParameters, DhPublicKey};

    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind};

    #[test]
    fn a_generated_group_gives_key_pairs_of_that_group() {
        let algo = DefaultAlgoBuilder::default().build();
        let params = DhGroupGenerationParams::new().with_size(256);
        let group = algo
            .params_generator()
            .generate_by_name_with("DH_GROUP", &params)
            .unwrap();
        let group = group.as_any().downcast_ref::<DhParameters>().unwrap();
        assert_eq!(group.p().bits(), 256);

        let pair = algo
            .key_pair_generator()
            .generate_by_name_with("DH", group)
            .unwrap();
        let public = pair
            .public()
            .as_any()
            .downcast_ref::<DhPublicKey>()
            .unwrap();
        assert_eq!(public.params(), group);
    }

    #[test]
    fn params_the_generator_turns_down_are_invalid_at_init() {
        let algo = DefaultAlgoBuilder::default().build();
        let mut generator = algo.params_generator().get_by_name("DH_GROUP").unwrap();
        let too_small = DhGroupGenerationParams::new().with_size(32);
        let error = generator.init(&too_small).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }

    #[test]
    fn params_of_another_type_are_invalid() {
        let algo = DefaultAlgoBuilder::default().build();
        let mut generator = algo.params_generator().get_by_name("DH_GROUP").unwrap();
        let error = generator
            .init(&crate::params::key::dh_groups::rfc3526_2048())
            .err()
            .unwrap();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }

    #[test]
    fn an_unknown_name_is_an_unknown_params_generator() {
        let algo = DefaultAlgoBuilder::default().build();
        let error = algo.params_generator().get_by_name("NOPE").err().unwrap();
        assert_eq!(error.kind(), ErrorKind::UnknownParamsGenerator);
    }
}
