//! Name- and OID-based factories for algorithms, after Bouncy Castle's `Org.BouncyCastle.Security`.
//! Everything starts from an [`Algo`], whose methods give one factory for each kind of algorithm.

mod agreement;
mod algo;
mod cipher;
mod codec;
mod digest;
mod error;
mod generate;
mod kem;
mod mac;
mod need;
mod params;
mod pbe;
mod policy;
mod signer;
mod wrap;
mod xof;

pub use agreement::{
    Agreement, AgreementEntry, AgreementFactory, AgreementInit, AgreementPeer, AnyAgreement,
    AnyAgreementParams, SharedSecret,
};
pub use algo::Algo;
pub use cipher::{
    AnyCipher, BufferedCipher, BufferedCipherInit, CipherDirection, CipherEntry, CipherFactory,
};
pub use digest::{AnyDigest, Digest, DigestEntry, DigestFactory, TryDigest};
pub use error::{AlgoError, ErrorKind};
pub use generate::KeyGenParams;
#[cfg(feature = "rsa")]
pub use generate::RsaKeyGenParams;
pub use generate::key::{KeyGenerator, KeyGeneratorEntry, KeyGeneratorFactory};
pub use generate::key_pair::{
    KeyPair, KeyPairGenerator, KeyPairGeneratorEntry, KeyPairGeneratorFactory,
};
pub use mac::{AnyMac, AnyMacParams, Mac, MacEntry, MacFactory, MacInit};
#[cfg(feature = "ec")]
pub use params::{AnyEcPrivateKey, AnyEcPublicKey, EcCurve};
pub use params::{AnyKeyParams, AnyOpParams, AnyParams, AnyPrivateKey, AnyPublicKey, SecretKey};
pub use policy::Policy;
pub use xof::{AnyXof, AnyXofParams, XofEntry, XofFactory};
