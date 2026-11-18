use tc_asn1::Asn1Oid;

use super::typed::{Erased, Inner, init_as};
use crate::agreement::{Agreement, AgreementEntry};
use crate::{AlgoError, DefaultAlgoContext, EntryBase, Params};

type Init = fn(&dyn Params) -> Option<Result<Box<dyn Inner>, AlgoError>>;

// The rows of X25519 and X448 of RFC 7748, to give to DefaultAlgoBuilder::reg_agreement, with the
// names and OIDs of Bouncy Castle's AgreementUtilities. The params of each are its private key,
// the other side's key its public key; the secret is 32 or 56 bytes
pub(super) fn cfrg(_context: &DefaultAlgoContext) -> Vec<Box<dyn AgreementEntry>> {
    let mut rows: Vec<Box<dyn AgreementEntry>> = Vec::new();
    #[cfg(feature = "cfrg-curves")]
    rows.push(row("X25519", "1.3.101.110", x25519));
    #[cfg(feature = "cfrg-curves")]
    rows.push(row("X448", "1.3.101.111", x448));
    rows
}

struct Row {
    name: &'static str,
    oids: Vec<Asn1Oid>,
    init: Init,
}

fn row(name: &'static str, oid: &str, init: Init) -> Box<dyn AgreementEntry> {
    Box::new(Row {
        name,
        oids: vec![oid.parse().expect("a dotted OID")],
        init,
    })
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        self.name
    }

    fn oids(&self) -> &[Asn1Oid] {
        &self.oids
    }
}

impl AgreementEntry for Row {
    fn create(&self) -> Option<Box<dyn Agreement>> {
        Some(Erased::boxed(self.init))
    }
}

#[cfg(feature = "cfrg-curves")]
fn x25519(params: &dyn Params) -> Option<Result<Box<dyn Inner>, AlgoError>> {
    init_as::<tc_cfrg_curves::X25519PrivateKey, _>(tc_cfrg_curves::X25519Agreement::new(), params)
}

#[cfg(feature = "cfrg-curves")]
fn x448(params: &dyn Params) -> Option<Result<Box<dyn Inner>, AlgoError>> {
    init_as::<tc_cfrg_curves::X448PrivateKey, _>(tc_cfrg_curves::X448Agreement::new(), params)
}

#[cfg(test)]
mod tests {
    use crate::{AlgoBuilder, DefaultAlgoBuilder, Params};

    fn secret(name: &str, private: &dyn Params, public: &dyn Params) -> Vec<u8> {
        let algo = DefaultAlgoBuilder::default().build();
        let mut agreement = algo.agreement().get_by_name(name).unwrap();
        agreement.init(private).unwrap();
        let mut secret = vec![0; agreement.agreement_size()];
        agreement.calculate_agreement(public, &mut secret).unwrap();
        secret
    }

    #[cfg(feature = "cfrg-curves")]
    #[test]
    fn both_sides_of_x25519_calculate_the_same_32_byte_secret() {
        use tc_cfrg_curves::X25519PrivateKey;
        let (alice, bob) = (
            X25519PrivateKey::new([7; 32]),
            X25519PrivateKey::new([9; 32]),
        );
        let shared = secret("X25519", &alice, &bob.generate_public_key());
        assert_eq!(shared, secret("X25519", &bob, &alice.generate_public_key()));
        assert_eq!(shared.len(), 32);
    }

    #[cfg(feature = "cfrg-curves")]
    #[test]
    fn both_sides_of_x448_calculate_the_same_56_byte_secret() {
        use tc_cfrg_curves::X448PrivateKey;
        let (alice, bob) = (X448PrivateKey::new([7; 56]), X448PrivateKey::new([9; 56]));
        let shared = secret("X448", &alice, &bob.generate_public_key());
        assert_eq!(shared, secret("X448", &bob, &alice.generate_public_key()));
        assert_eq!(shared.len(), 56);
    }
}
