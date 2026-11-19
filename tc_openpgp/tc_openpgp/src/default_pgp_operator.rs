use std::collections::HashMap;

use tc_algo::{AlgoError, ErrorKind};
use tc_openpgp_packet::PublicKeyAlgorithmTag;

use crate::key_pair_generator::GeneratorFactory;
use crate::{
    DefaultPgpOperatorContext, PgpKeyPairGenerator, PgpKeyPairGeneratorProvider, PgpOperator,
};

pub(crate) struct DefaultPgpOperator {
    pub(crate) context: DefaultPgpOperatorContext,
    pub(crate) generators: HashMap<PublicKeyAlgorithmTag, GeneratorFactory>,
}

impl PgpOperator for DefaultPgpOperator {
    fn key_pair_generator(&self) -> &dyn PgpKeyPairGeneratorProvider {
        self
    }
}

impl PgpKeyPairGeneratorProvider for DefaultPgpOperator {
    fn get_by_algorithm(
        &self,
        tag: PublicKeyAlgorithmTag,
    ) -> Result<Box<dyn PgpKeyPairGenerator>, AlgoError> {
        let create = self
            .generators
            .get(&tag)
            .ok_or_else(|| AlgoError::new(ErrorKind::UnknownGenerator))?;
        Ok(create(&self.context))
    }
}
