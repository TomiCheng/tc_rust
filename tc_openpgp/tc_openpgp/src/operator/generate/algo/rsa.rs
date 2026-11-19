use std::sync::Arc;

use tc_algo::{Algo, AlgoError, Params};
use tc_openpgp_packet::PublicKeyAlgorithmTag;

use crate::operator::generate::PgpKeyPairGenerator;
use crate::{DefaultPgpOperatorContext, PgpPrivateKey, PgpPublicKey};

pub(super) fn create(context: &DefaultPgpOperatorContext) -> Box<dyn PgpKeyPairGenerator> {
    Box::new(RsaGenerator(context.algo().clone()))
}

struct RsaGenerator(Arc<dyn Algo>);

impl PgpKeyPairGenerator for RsaGenerator {
    fn generate(
        &mut self,
        params: &dyn Params,
    ) -> Result<(PgpPublicKey, PgpPrivateKey), AlgoError> {
        let pair = self
            .0
            .key_pair_generator()
            .generate_by_name_with("RSA", params)?;
        let (public, private) = pair.into_parts();
        let tag = PublicKeyAlgorithmTag::RsaGeneral;
        Ok((
            PgpPublicKey::new(tag, public),
            PgpPrivateKey::new(tag, private),
        ))
    }
}
