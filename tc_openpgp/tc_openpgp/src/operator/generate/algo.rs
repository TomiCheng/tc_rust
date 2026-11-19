#[cfg(feature = "cfrg-curves")]
mod curve25519;
#[cfg(any(feature = "rsa", feature = "cfrg-curves"))]
mod generator;
#[cfg(feature = "rsa")]
mod rsa;

use tc_openpgp_packet::PublicKeyAlgorithmTag;

use super::PgpKeyPairGenerator;
use crate::DefaultPgpOperatorContext;

type CreateGenerator =
    fn(&DefaultPgpOperatorContext) -> Result<Box<dyn PgpKeyPairGenerator>, tc_algo::AlgoError>;

pub(crate) const BUILT_IN: &[(PublicKeyAlgorithmTag, CreateGenerator)] = &[
    #[cfg(feature = "rsa")]
    (PublicKeyAlgorithmTag::RsaGeneral, rsa::create),
    #[cfg(feature = "cfrg-curves")]
    (PublicKeyAlgorithmTag::Ed25519, curve25519::ed25519),
    #[cfg(feature = "cfrg-curves")]
    (PublicKeyAlgorithmTag::X25519, curve25519::x25519),
];
