mod dsa;
mod ecdsa;
mod eddsa;
mod pss;
mod rsa;

use tc_algo::Algo;
use tc_algo::signer::Signer;
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::operator::signer::SignerEntry;
use crate::{DefaultX509OperatorContext, X509Error};

pub(crate) type CreateRows = fn(&DefaultX509OperatorContext) -> Vec<Box<dyn SignerEntry>>;

// What DefaultX509OperatorBuilder starts with. These are always on, as a certificate needs them
pub(crate) const BUILT_IN: &[CreateRows] =
    &[rsa::rsa, pss::pss, ecdsa::ecdsa, eddsa::eddsa, dsa::dsa];

// A row whose AlgorithmIdentifier is an OID alone, or with the NULL of RSA, and whose signer is
// the row of tc_algo by that OID
struct ByOid {
    name: &'static str,
    aliases: Vec<String>,
    algorithm: AlgorithmIdentifier,
}

impl ByOid {
    // `aliases` are the other names of Bouncy Castle's Asn1SignatureFactory
    fn boxed(
        name: &'static str,
        aliases: &[&str],
        algorithm: AlgorithmIdentifier,
    ) -> Box<dyn SignerEntry> {
        Box::new(Self {
            name,
            aliases: aliases.iter().map(|alias| alias.to_string()).collect(),
            algorithm,
        })
    }
}

impl SignerEntry for ByOid {
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

fn oid(dotted: &str) -> tc_asn1::Asn1Oid {
    dotted.parse().expect("the OIDs of the rows are valid")
}
