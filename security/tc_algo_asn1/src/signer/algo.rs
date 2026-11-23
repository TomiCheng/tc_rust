mod dsa;
mod ecdsa;
mod eddsa;
mod pss;
mod rsa;
mod sm2;

use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::DefaultAlgoAsn1Context;
use crate::signer::SignerEntry;

pub(crate) type CreateRows = fn(&DefaultAlgoAsn1Context) -> Vec<Box<dyn SignerEntry>>;

// What DefaultAlgoAsn1Builder starts with. These are always on, as a certificate needs them
pub(crate) const BUILT_IN: &[CreateRows] = &[
    rsa::rsa,
    pss::pss,
    ecdsa::ecdsa,
    eddsa::eddsa,
    dsa::dsa,
    sm2::sm2,
];

// A row whose AlgorithmIdentifier is an OID alone, or with the NULL of RSA
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
}

fn oid(dotted: &str) -> tc_asn1::Asn1Oid {
    dotted.parse().expect("the OIDs of the rows are valid")
}
