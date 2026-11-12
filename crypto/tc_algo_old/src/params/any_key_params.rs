use super::{AnyPrivateKey, AnyPublicKey, SecretKey};

// The IES variant comes with the algorithm that uses it
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum AnyKeyParams {
    Secret(SecretKey),
    Private(AnyPrivateKey),
    Public(AnyPublicKey),
}
