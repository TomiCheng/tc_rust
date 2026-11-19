#[cfg(feature = "rsa")]
mod rsa;

use tc_openpgp_packet::PublicKeyAlgorithmTag;

use super::PgpKeyPairGenerator;
use crate::DefaultPgpOperatorContext;

type CreateGenerator = fn(&DefaultPgpOperatorContext) -> Box<dyn PgpKeyPairGenerator>;

pub(crate) const BUILT_IN: &[(PublicKeyAlgorithmTag, CreateGenerator)] = &[
    #[cfg(feature = "rsa")]
    (PublicKeyAlgorithmTag::RsaGeneral, rsa::create),
];
