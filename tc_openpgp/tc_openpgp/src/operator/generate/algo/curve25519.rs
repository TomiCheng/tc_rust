use std::sync::Arc;

use tc_algo::{Algo, AlgoError, ErrorKind, Params};
use tc_openpgp_packet::PublicKeyAlgorithmTag;

use crate::operator::generate::PgpKeyPairGenerator;
use crate::{DefaultPgpOperatorContext, PgpPrivateKey, PgpPublicKey};

struct CurveGenerator {
    algo: Arc<dyn Algo>,
    tag: PublicKeyAlgorithmTag,
    name: &'static str,
}

pub(super) fn ed25519(ctx: &DefaultPgpOperatorContext) -> Box<dyn PgpKeyPairGenerator> {
    Box::new(CurveGenerator {
        algo: ctx.algo().clone(),
        tag: PublicKeyAlgorithmTag::Ed25519,
        name: "Ed25519",
    })
}

pub(super) fn x25519(ctx: &DefaultPgpOperatorContext) -> Box<dyn PgpKeyPairGenerator> {
    Box::new(CurveGenerator {
        algo: ctx.algo().clone(),
        tag: PublicKeyAlgorithmTag::X25519,
        name: "X25519",
    })
}

impl PgpKeyPairGenerator for CurveGenerator {
    fn generate(
        &mut self,
        _params: &dyn Params,
    ) -> Result<(PgpPublicKey, PgpPrivateKey), AlgoError> {
        Err(AlgoError::new(ErrorKind::InvalidKeyGenParams))
    }

    fn generate_without_params(&mut self) -> Result<(PgpPublicKey, PgpPrivateKey), AlgoError> {
        let (public, private) = self
            .algo
            .key_pair_generator()
            .generate_by_name(self.name)?
            .into_parts();
        Ok((
            PgpPublicKey::new(self.tag, public),
            PgpPrivateKey::new(self.tag, private),
        ))
    }
}
