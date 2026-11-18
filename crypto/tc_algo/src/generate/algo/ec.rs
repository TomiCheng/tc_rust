use rand_core::CryptoRng;
use tc_asn1::Asn1Oid;

use crate::generate::{KeyPairGenerator, KeyPairGeneratorEntry};
use crate::params::ec_curves::NamedCurve;
use crate::params::generate::EcKeyGenParams;
use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind, Params};

// The row of EC, to give to DefaultAlgoBuilder::reg_key_pair_generator. Bouncy Castle's
// GeneratorUtilities names EC, ECDH, ECIES, ECDHC, ECMQV and ECDSA, all of them its
// ECKeyPairGenerator, with the OIDs of the X9.63 and SEC schemes of DH and MQV; here they are one
// row
pub(super) fn ec(context: &DefaultAlgoContext) -> Vec<Box<dyn KeyPairGeneratorEntry>> {
    let oids = [
        // dhSinglePass, standard DH: SHA-1 of X9.63, then SHA-224 to SHA-512 of SEC
        "1.3.133.16.840.63.0.2",
        "1.3.132.1.11.0",
        "1.3.132.1.11.1",
        "1.3.132.1.11.2",
        "1.3.132.1.11.3",
        // dhSinglePass, cofactor DH
        "1.3.133.16.840.63.0.3",
        "1.3.132.1.14.0",
        "1.3.132.1.14.1",
        "1.3.132.1.14.2",
        "1.3.132.1.14.3",
        // mqvSinglePass
        "1.3.133.16.840.63.0.16",
        "1.3.132.1.15.0",
        "1.3.132.1.15.1",
        "1.3.132.1.15.2",
        "1.3.132.1.15.3",
    ];
    vec![Box::new(Row {
        aliases: [
            "ECDH",
            "ECIES",
            "ECDHC",
            "ECMQV",
            "ECDSA",
            "ECGOST3410",
            "ECGOST-3410",
            "GOST-3410-2001",
            "ECGOST3410-2012",
            "GOST-3410-2012",
        ]
        .map(String::from)
        .to_vec(),
        oids: oids
            .iter()
            .map(|dotted| dotted.parse().expect("a valid OID"))
            .collect(),
        rand: context.rand(),
    })]
}

struct Row {
    aliases: Vec<String>,
    oids: Vec<Asn1Oid>,
    rand: fn() -> Box<dyn CryptoRng>,
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        "EC"
    }

    fn aliases(&self) -> &[String] {
        &self.aliases
    }

    fn oids(&self) -> &[Asn1Oid] {
        &self.oids
    }
}

impl KeyPairGeneratorEntry for Row {
    fn create(&self) -> Box<dyn KeyPairGenerator> {
        Box::new(Ec {
            rand: (self.rand)(),
            curve: None,
        })
    }
}

// Its params are an EcKeyGenParams. There is no default curve, since several curves have one size
// and guessing would pick a wrong one quietly, so generate needs init
struct Ec {
    rand: Box<dyn CryptoRng>,
    curve: Option<&'static NamedCurve>,
}

impl tc_asym_cipher::KeyPairGenerator for Ec {
    type PublicKey = Box<dyn Params>;
    type PrivateKey = Box<dyn Params>;
    type Error = AlgoError;

    fn generate_key_pair(&mut self) -> Result<(Box<dyn Params>, Box<dyn Params>), AlgoError> {
        let curve = self
            .curve
            .ok_or(AlgoError::new(ErrorKind::NotInitialized))?;
        (curve.generate)(self.rand.as_mut())
    }
}

impl tc_asym_cipher::KeyPairGeneratorInit<dyn Params> for Ec {
    type Error = AlgoError;

    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError> {
        self.curve = None;
        let params = params
            .as_any()
            .downcast_ref::<EcKeyGenParams>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        self.curve = Some(
            params
                .named_curve()
                .ok_or(AlgoError::new(ErrorKind::InvalidParams))?,
        );
        Ok(())
    }
}

impl KeyPairGenerator for Ec {}

#[cfg(test)]
mod tests {
    use crate::params::ec_curves::CURVES;
    use crate::params::generate::EcKeyGenParams;
    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind};

    // Every curve of the table, by its first name or, for DSTU 4145, by its OID, gives a pair
    #[test]
    fn every_named_curve_gives_a_key_pair() {
        let algo = DefaultAlgoBuilder::default().build();
        let generators = algo.key_pair_generator();
        for curve in CURVES {
            let params = match curve.names.first() {
                Some(name) => EcKeyGenParams::new(*name),
                None => EcKeyGenParams::from_oid(curve.oid.parse().unwrap()),
            };
            generators
                .generate_by_name_with("EC", &params)
                .unwrap_or_else(|error| panic!("{}: {error}", curve.oid));
        }
        assert_eq!(CURVES.len(), 94);
    }

    #[test]
    fn the_aliases_and_names_find_the_same_curve() {
        let algo = DefaultAlgoBuilder::default().build();
        let generators = algo.key_pair_generator();
        for (row, name) in [
            ("ECDSA", "secp256r1"),
            ("ECDH", "prime256v1"),
            ("ecmqv", "p-256"),
            ("ECDHC", "K-163"),
        ] {
            generators
                .generate_by_name_with(row, &EcKeyGenParams::new(name))
                .unwrap_or_else(|error| panic!("{row} {name}: {error}"));
        }
        generators
            .generate_by_oid_with(
                &"1.3.132.1.11.1".parse().unwrap(),
                &EcKeyGenParams::new("P-256"),
            )
            .unwrap();
    }

    #[test]
    fn generate_needs_a_curve_the_table_has() {
        let algo = DefaultAlgoBuilder::default().build();
        let generators = algo.key_pair_generator();
        let error = generators.generate_by_name("EC").err().unwrap();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);

        let error = generators
            .generate_by_name_with("EC", &EcKeyGenParams::new("P-255"))
            .err()
            .unwrap();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}
