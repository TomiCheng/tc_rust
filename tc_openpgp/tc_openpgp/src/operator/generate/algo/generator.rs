use tc_algo::{AlgoError, Params};
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_openpgp_packet::PublicKeyAlgorithmTag;

use crate::{DefaultPgpOperatorContext, PgpKeyPairGenerator, PgpPrivateKey, PgpPublicKey};

struct Generator {
    inner: Box<dyn tc_algo::generate::KeyPairGenerator>,
    tag: PublicKeyAlgorithmTag,
}

pub(super) fn create(
    ctx: &DefaultPgpOperatorContext,
    tag: PublicKeyAlgorithmTag,
    name: &str,
) -> Result<Box<dyn PgpKeyPairGenerator>, AlgoError> {
    let inner = ctx.algo().key_pair_generator().get_by_name(name)?;
    Ok(Box::new(Generator { inner, tag }))
}

impl KeyPairGeneratorInit<dyn Params> for Generator {
    type Error = AlgoError;

    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError> {
        self.inner.init(params)
    }
}

impl KeyPairGenerator for Generator {
    type PublicKey = PgpPublicKey;
    type PrivateKey = PgpPrivateKey;
    type Error = AlgoError;

    fn generate_key_pair(&mut self) -> Result<(PgpPublicKey, PgpPrivateKey), AlgoError> {
        let (public, private) = self.inner.generate_key_pair()?;
        Ok((
            PgpPublicKey::new(self.tag, public),
            PgpPrivateKey::new(self.tag, private),
        ))
    }
}

impl PgpKeyPairGenerator for Generator {}
