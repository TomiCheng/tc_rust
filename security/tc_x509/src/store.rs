//! Finding certificates and revocations among many: BC's `X509CertStoreSelector`, and a store
//! of CRLs. A collection of certificates is a `Vec` or any iterator:
//! `certs.iter().filter(|c| selector.matches(c))`.

mod x509_cert_selector;
mod x509_crl_store;

pub use x509_cert_selector::X509CertSelector;
pub use x509_crl_store::X509CrlStore;
