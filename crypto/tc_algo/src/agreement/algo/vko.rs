use tc_bigint::PaddedBigUint;
use tc_digest::Digest;
use tc_ec_core::Curve;
use tc_ecvko::{EcVkoAgreement, EcVkoParams};
use tc_gost3411::{Gost3411_2012_256Digest, Gost3411_2012_512Digest, Gost3411Digest};

use super::typed::{Erased, Inner, init_as};
use crate::agreement::{Agreement, AgreementEntry};
use crate::params::ec_curves::ct_curves;
use crate::{AlgoError, DefaultAlgoContext, EntryBase, Params};
use tc_asn1::Asn1Oid;

type Try = fn(&dyn Params) -> Option<Result<Box<dyn Inner>, AlgoError>>;

// The rows of VKO, the GOST R 34.10 key agreement, to give to DefaultAlgoBuilder::reg_agreement:
// ECGOST3410 over GOST R 34.11-94 and ECGOST3410-2012-256 and -512 over Streebog, with the names,
// aliases and OIDs of Bouncy Castle's AgreementUtilities. Its params are an EcVkoParams of the
// private key and the UKM, the other side's key an EcPublicKey; the curve comes from the keys
pub(super) fn vko(_context: &DefaultAlgoContext) -> Vec<Box<dyn AgreementEntry>> {
    vec![
        row(
            "ECGOST3410",
            &["GOST-3410-2001"],
            &["1.2.643.2.2.19", "1.2.643.2.2.96"],
            ct_curves!(gost3411),
        ),
        row(
            "ECGOST3410-2012-256",
            &[],
            &["1.2.643.7.1.1.6.1", "1.2.643.7.1.1.1.1"],
            ct_curves!(gost3411_2012_256),
        ),
        row(
            "ECGOST3410-2012-512",
            &[],
            &["1.2.643.7.1.1.6.2", "1.2.643.7.1.1.1.2"],
            ct_curves!(gost3411_2012_512),
        ),
    ]
}

struct Row {
    name: &'static str,
    aliases: Vec<String>,
    oids: Vec<Asn1Oid>,
    tries: &'static [Try],
}

fn row(
    name: &'static str,
    aliases: &[&str],
    oids: &[&str],
    tries: &'static [Try],
) -> Box<dyn AgreementEntry> {
    Box::new(Row {
        name,
        aliases: aliases.iter().map(|alias| alias.to_string()).collect(),
        oids: oids
            .iter()
            .map(|oid| oid.parse().expect("a dotted OID"))
            .collect(),
        tries,
    })
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        self.name
    }

    fn aliases(&self) -> &[String] {
        &self.aliases
    }

    fn oids(&self) -> &[Asn1Oid] {
        &self.oids
    }
}

impl AgreementEntry for Row {
    fn create(&self) -> Option<Box<dyn Agreement>> {
        let tries = self.tries;
        Some(Erased::boxed(move |params: &dyn Params| {
            tries.iter().find_map(|init| init(params))
        }))
    }
}

fn init<C, D>(params: &dyn Params, digest: D) -> Option<Result<Box<dyn Inner>, AlgoError>>
where
    C: Curve<Scalar = PaddedBigUint> + 'static,
    D: Digest + Clone + 'static,
{
    init_as::<EcVkoParams<C>, _>(EcVkoAgreement::<C, D>::new(digest), params)
}

fn gost3411<C: Curve<Scalar = PaddedBigUint> + 'static>(
    params: &dyn Params,
) -> Option<Result<Box<dyn Inner>, AlgoError>> {
    init::<C, _>(params, Gost3411Digest::new())
}

fn gost3411_2012_256<C: Curve<Scalar = PaddedBigUint> + 'static>(
    params: &dyn Params,
) -> Option<Result<Box<dyn Inner>, AlgoError>> {
    init::<C, _>(params, Gost3411_2012_256Digest::new())
}

fn gost3411_2012_512<C: Curve<Scalar = PaddedBigUint> + 'static>(
    params: &dyn Params,
) -> Option<Result<Box<dyn Inner>, AlgoError>> {
    init::<C, _>(params, Gost3411_2012_512Digest::new())
}

#[cfg(test)]
mod tests {
    use rand::rngs::SysRng;
    use rand_core::UnwrapErr;
    use tc_ec_key::EcPrivateKey;
    use tc_ecvko::EcVkoParams;
    use tc_fp_curve::FpCtCurve;

    use crate::params::ec_curves::by_name;
    use crate::{AlgoBuilder, DefaultAlgoBuilder, Params};

    type Gost = &'static FpCtCurve<'static>;

    #[test]
    fn both_sides_calculate_the_same_secret_of_the_size_of_each_digest() {
        let algo = DefaultAlgoBuilder::default().build();
        let curve = by_name("GostR3410-2001-CryptoPro-A").unwrap();
        let pair = || (curve.generate)(&mut UnwrapErr(SysRng)).unwrap();
        let (alice_public, alice_private) = pair();
        let (bob_public, bob_private) = pair();
        let ukm = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let params = |private: &dyn Params| {
            let key = private
                .as_any()
                .downcast_ref::<EcPrivateKey<Gost>>()
                .unwrap();
            EcVkoParams::new(key.clone(), ukm.clone())
        };
        for (name, size) in [
            ("ECGOST3410", 32),
            ("GOST-3410-2001", 32),
            ("ECGOST3410-2012-256", 32),
            ("ECGOST3410-2012-512", 64),
        ] {
            let secret = |private: &dyn Params, public: &dyn Params| {
                let mut agreement = algo.agreement().get_by_name(name).unwrap();
                agreement.init(&params(private)).unwrap();
                let mut secret = vec![0; agreement.agreement_size()];
                agreement.calculate_agreement(public, &mut secret).unwrap();
                secret
            };
            let alice = secret(alice_private.as_ref(), bob_public.as_ref());
            let bob = secret(bob_private.as_ref(), alice_public.as_ref());
            assert_eq!(alice, bob, "{name}");
            assert_eq!(alice.len(), size, "{name}");
        }
    }
}
