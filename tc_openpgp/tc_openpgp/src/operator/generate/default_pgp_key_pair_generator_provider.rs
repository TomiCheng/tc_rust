use std::collections::HashMap;

use tc_algo::{AlgoError, ErrorKind};
use tc_openpgp_packet::PublicKeyAlgorithmTag;

use super::{GeneratorFactory, PgpKeyPairGenerator, PgpKeyPairGeneratorProvider};
use crate::DefaultPgpOperatorContext;

pub(crate) struct DefaultPgpKeyPairGeneratorProvider {
    pub(crate) context: DefaultPgpOperatorContext,
    pub(crate) generators: HashMap<PublicKeyAlgorithmTag, GeneratorFactory>,
}

impl PgpKeyPairGeneratorProvider for DefaultPgpKeyPairGeneratorProvider {
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
