use crate::pkcs8::Pkcs8Provider;
use crate::spki::SpkiProvider;

// The conversions between tc_algo and ASN.1, one provider per kind
pub trait AlgoAsn1: Send + Sync {
    fn spki(&self) -> &dyn SpkiProvider;

    fn pkcs8(&self) -> &dyn Pkcs8Provider;
}
