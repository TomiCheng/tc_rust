//! Verifying signatures under an `AlgorithmIdentifier`.

mod default_verifier_factory;
mod default_verifier_factory_provider;
mod verifier_factory;
mod verifier_factory_provider;
mod verifier_trait;

pub(crate) use default_verifier_factory::DefaultVerifierFactory;
pub(crate) use default_verifier_factory_provider::DefaultVerifierFactoryProvider;
pub use verifier_factory::VerifierFactory;
pub use verifier_factory_provider::VerifierFactoryProvider;
pub use verifier_trait::Verifier;
