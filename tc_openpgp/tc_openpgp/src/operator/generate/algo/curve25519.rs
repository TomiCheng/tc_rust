use tc_algo::AlgoError;
use tc_openpgp_packet::PublicKeyAlgorithmTag;

use crate::{DefaultPgpOperatorContext, PgpKeyPairGenerator};

pub(super) fn ed25519(
    ctx: &DefaultPgpOperatorContext,
) -> Result<Box<dyn PgpKeyPairGenerator>, AlgoError> {
    super::generator::create(ctx, PublicKeyAlgorithmTag::Ed25519, "Ed25519")
}

pub(super) fn x25519(
    ctx: &DefaultPgpOperatorContext,
) -> Result<Box<dyn PgpKeyPairGenerator>, AlgoError> {
    super::generator::create(ctx, PublicKeyAlgorithmTag::X25519, "X25519")
}
