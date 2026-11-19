use tc_algo::AlgoError;
use tc_openpgp_packet::PublicKeyAlgorithmTag;

use crate::{DefaultPgpOperatorContext, PgpKeyPairGenerator};

pub(super) fn create(
    ctx: &DefaultPgpOperatorContext,
) -> Result<Box<dyn PgpKeyPairGenerator>, AlgoError> {
    super::generator::create(ctx, PublicKeyAlgorithmTag::RsaGeneral, "RSA")
}
