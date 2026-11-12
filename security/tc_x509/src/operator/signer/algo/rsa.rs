use tc_algo::Algo;
use tc_algo::signer::Signer;
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::operator::signer::SignerEntry;
use crate::{DefaultX509OperatorContext, X509Error};

// The rows of RSA. The names are those of Bouncy Castle, and the parameters are NULL, as RFC 4055
// section 5 requires of PKCS #1 v1.5
pub(super) fn rsa(_context: &DefaultX509OperatorContext) -> Vec<Box<dyn SignerEntry>> {
    vec![Box::new(Rsa {
        name: "SHA-256withRSA",
        aliases: vec![
            "SHA256withRSA".to_string(),
            "SHA256withRSAEncryption".to_string(),
            "SHA-256withRSAEncryption".to_string(),
        ],
        algorithm: AlgorithmIdentifier::with_null(
            "1.2.840.113549.1.1.11"
                .parse()
                .expect("sha256WithRSAEncryption is a valid OID"),
        ),
    })]
}

struct Rsa {
    name: &'static str,
    aliases: Vec<String>,
    algorithm: AlgorithmIdentifier,
}

impl SignerEntry for Rsa {
    fn name(&self) -> &str {
        self.name
    }

    fn aliases(&self) -> &[String] {
        &self.aliases
    }

    fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.algorithm
    }

    fn create(&self, algo: &dyn Algo) -> Result<Box<dyn Signer>, X509Error> {
        Ok(algo.signer().get_by_oid(self.algorithm.algorithm())?)
    }
}
