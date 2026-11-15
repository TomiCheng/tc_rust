use core::any::Any;

use tc_asn1::Asn1Oid;

use crate::Params;
use crate::params::ec_curves::{self, NamedCurve};

// The params of the EC key pair generator: the curve, by a name of Bouncy Castle's
// ECNamedCurveTable, such as secp256r1, prime256v1 or P-256, or by its OID. They are not checked
// until init, which gives InvalidParams for a curve the table does not have
pub struct EcKeyGenParams {
    curve: Curve,
}

enum Curve {
    Name(String),
    Oid(Asn1Oid),
}

impl EcKeyGenParams {
    // The curve of `name`, in any case
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            curve: Curve::Name(name.into()),
        }
    }

    // The curve of `oid`
    pub fn from_oid(oid: Asn1Oid) -> Self {
        Self {
            curve: Curve::Oid(oid),
        }
    }

    pub(crate) fn named_curve(&self) -> Option<&'static NamedCurve> {
        match &self.curve {
            Curve::Name(name) => ec_curves::by_name(name),
            Curve::Oid(oid) => ec_curves::by_oid(oid),
        }
    }
}

impl Params for EcKeyGenParams {
    fn as_any(&self) -> &dyn Any {
        self
    }
}
