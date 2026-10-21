//! X.509 certificates, after Bouncy Castle's `Org.BouncyCastle.X509`, over the structures
//! of `tc_asn1_x509`.

#![no_std]

mod x509_certificate;

pub use x509_certificate::X509Certificate;
