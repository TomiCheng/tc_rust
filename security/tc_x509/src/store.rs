//! Finding certificates and revocations among many: BC's `X509CertStoreSelector`, a store of
//! certificates that answers it through an index, and a store of CRLs. Any `Vec` or iterator of
//! certificates takes the selector too: `certs.iter().filter(|c| selector.matches(c))`.

mod x509_cert_selector;
mod x509_certificate_store;
mod x509_crl_store;

pub use x509_cert_selector::X509CertSelector;
pub use x509_certificate_store::X509CertificateStore;
pub use x509_crl_store::X509CrlStore;
