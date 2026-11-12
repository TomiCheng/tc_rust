//! Selectors that find certificates among others, BC's `X509CertStoreSelector`. A
//! collection of them is a `Vec` or any iterator: `certs.iter().filter(|c|
//! selector.matches(c))`.

mod x509_cert_selector;

pub use x509_cert_selector::X509CertSelector;
