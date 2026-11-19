//! OpenPGP 的金鑰、簽章與加密，對應 Bouncy Castle 的 `Org.BouncyCastle.Bcpg.OpenPgp`。

mod default_pgp_operator;
mod default_pgp_operator_builder;
mod default_pgp_operator_context;
pub mod operator;
mod pgp_private_key;
mod pgp_public_key;
mod traits;

pub use default_pgp_operator_builder::DefaultPgpOperatorBuilder;
pub use default_pgp_operator_context::DefaultPgpOperatorContext;
pub use operator::generate::{PgpKeyPairGenerator, PgpKeyPairGeneratorProvider};
pub use pgp_private_key::PgpPrivateKey;
pub use pgp_public_key::PgpPublicKey;
pub use traits::{PgpOperator, PgpOperatorBuilder};
