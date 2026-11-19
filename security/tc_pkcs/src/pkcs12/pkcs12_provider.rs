use tc_x509::cert::X509Certificate;

use crate::PkcsError;
use crate::pkcs12::{Pkcs12Options, Pkcs12Store};

pub trait Pkcs12Provider: Send + Sync {
    // Bouncy Castle's Load. With a MAC, the password is needed and has to verify it: MissingPassword
    // without one, InvalidMac for a wrong one. CRLs, secrets and nested bags are skipped, as there
    fn load(&self, der: &[u8], password: Option<&str>) -> Result<Pkcs12Store, PkcsError>;

    // Bouncy Castle's Save, in DER. Without a password, nothing is encrypted and there is no MAC
    fn save(
        &self,
        store: &Pkcs12Store,
        password: Option<&str>,
        options: &Pkcs12Options,
    ) -> Result<Vec<u8>, PkcsError>;

    // Bouncy Castle's GetCertificateChain: from the certificate of the key under the alias to its
    // root, by the authority key identifier, or else by the issuer's name and a signature that
    // verifies. None when the alias is not a key's or the key has no certificate
    fn certificate_chain(&self, store: &Pkcs12Store, alias: &str) -> Option<Vec<X509Certificate>>;
}
