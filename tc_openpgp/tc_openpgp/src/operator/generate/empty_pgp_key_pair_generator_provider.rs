use tc_algo::{AlgoError, ErrorKind};
use tc_openpgp_packet::PublicKeyAlgorithmTag;

use super::{PgpKeyPairGenerator, PgpKeyPairGeneratorProvider};

pub(crate) struct EmptyPgpKeyPairGeneratorProvider;

impl PgpKeyPairGeneratorProvider for EmptyPgpKeyPairGeneratorProvider {
    fn get_by_algorithm(
        &self,
        _tag: PublicKeyAlgorithmTag,
    ) -> Result<Box<dyn PgpKeyPairGenerator>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownGenerator))
    }
}
