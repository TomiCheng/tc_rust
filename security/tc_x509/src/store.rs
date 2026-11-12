//! Finding certificates, CRLs and attribute certificates among many: BC's store selectors, a
//! store of certificates that answers a selector through an index, and a store of CRLs. Any
//! `Vec` or iterator takes a selector too: `certs.iter().filter(|c| selector.matches(c))`.

mod x509_attr_cert_selector;
mod x509_cert_selector;
mod x509_certificate_store;
mod x509_crl_selector;
mod x509_crl_store;

pub use x509_attr_cert_selector::X509AttrCertSelector;
pub use x509_cert_selector::X509CertSelector;
pub use x509_certificate_store::X509CertificateStore;
pub use x509_crl_selector::X509CrlSelector;
pub use x509_crl_store::X509CrlStore;
