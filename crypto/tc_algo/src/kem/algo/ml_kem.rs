use rand_core::CryptoRng;
use tc_asn1::Asn1Oid;
use tc_kem::{KemDecapsulator, KemEncapsulator, KemInit};
use tc_ml_kem::{
    MlKemDecapsulator, MlKemEncapsulator, MlKemError, MlKemParameters, MlKemPrivateKey,
    MlKemPublicKey,
};

use crate::agreement::SharedSecret;
use crate::kem::{Kem, KemEntry};
use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind, Params};

// The rows of ML-KEM (FIPS 203), to give to DefaultAlgoBuilder::reg_kem. Their names and OIDs are
// those of Bouncy Castle's MLKemParameters
pub(super) fn ml_kem(context: &DefaultAlgoContext) -> Vec<Box<dyn KemEntry>> {
    let rand = context.rand();
    vec![
        row(MlKemParameters::ML_KEM_512, "2.16.840.1.101.3.4.4.1", rand),
        row(MlKemParameters::ML_KEM_768, "2.16.840.1.101.3.4.4.2", rand),
        row(MlKemParameters::ML_KEM_1024, "2.16.840.1.101.3.4.4.3", rand),
    ]
}

fn row(
    params: MlKemParameters,
    dotted: &str,
    rand: fn() -> Box<dyn CryptoRng>,
) -> Box<dyn KemEntry> {
    Box::new(Row {
        params,
        oids: vec![dotted.parse().expect("a valid OID")],
        rand,
    })
}

struct Row {
    params: MlKemParameters,
    oids: Vec<Asn1Oid>,
    rand: fn() -> Box<dyn CryptoRng>,
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        self.params.name()
    }

    fn oids(&self) -> &[Asn1Oid] {
        &self.oids
    }
}

impl KemEntry for Row {
    fn create(&self) -> Box<dyn Kem> {
        Box::new(MlKem {
            params: self.params,
            rand: self.rand,
        })
    }
}

// Its keys are an MlKemPublicKey and an MlKemPrivateKey of the row's parameter set
struct MlKem {
    params: MlKemParameters,
    rand: fn() -> Box<dyn CryptoRng>,
}

impl Kem for MlKem {
    fn encapsulate(&self, public_key: &dyn Params) -> Result<(Vec<u8>, SharedSecret), AlgoError> {
        let key = public_key
            .as_any()
            .downcast_ref::<MlKemPublicKey>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        let mut encapsulator = MlKemEncapsulator::new(self.params, (self.rand)());
        encapsulator.init(key).map_err(algo_error)?;

        let mut encapsulation = vec![0; encapsulator.encapsulation_length()];
        let mut secret = vec![0; encapsulator.secret_length()];
        encapsulator
            .encapsulate(&mut encapsulation, &mut secret)
            .map_err(algo_error)?;
        Ok((encapsulation, SharedSecret::new(secret)))
    }

    fn decapsulate(
        &self,
        private_key: &dyn Params,
        encapsulation: &[u8],
    ) -> Result<SharedSecret, AlgoError> {
        let key = private_key
            .as_any()
            .downcast_ref::<MlKemPrivateKey>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        let mut decapsulator = MlKemDecapsulator::new(self.params);
        decapsulator.init(key).map_err(algo_error)?;

        let mut secret = vec![0; decapsulator.secret_length()];
        decapsulator
            .decapsulate(encapsulation, &mut secret)
            .map_err(algo_error)?;
        Ok(SharedSecret::new(secret))
    }
}

fn algo_error(error: MlKemError) -> AlgoError {
    let kind = match error {
        MlKemError::NotInitialized => ErrorKind::NotInitialized,
        MlKemError::InvalidEncapsulationLength | MlKemError::InvalidSecretLength => {
            ErrorKind::DataLength
        }
        _ => ErrorKind::InvalidParams,
    };
    AlgoError::with_source(kind, error)
}

#[cfg(test)]
mod tests {
    use tc_kem::{KemDecapsulator, KemInit};
    use tc_ml_kem::{MlKemDecapsulator, MlKemParameters, MlKemPrivateKey};

    use crate::generate::KeyPair;
    use crate::kem::Kem;
    use crate::params::KeyLength;
    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind};

    const ROWS: [(&str, MlKemParameters, &str, usize); 3] = [
        (
            "ML-KEM-512",
            MlKemParameters::ML_KEM_512,
            "2.16.840.1.101.3.4.4.1",
            768,
        ),
        (
            "ML-KEM-768",
            MlKemParameters::ML_KEM_768,
            "2.16.840.1.101.3.4.4.2",
            1088,
        ),
        (
            "ML-KEM-1024",
            MlKemParameters::ML_KEM_1024,
            "2.16.840.1.101.3.4.4.3",
            1568,
        ),
    ];

    fn pair(params: MlKemParameters) -> KeyPair {
        DefaultAlgoBuilder::default()
            .build()
            .key_pair_generator()
            .generate_by_name_with("ML-KEM", &params)
            .unwrap()
    }

    fn kem(name: &str) -> Box<dyn Kem> {
        DefaultAlgoBuilder::default()
            .build()
            .kem()
            .get_by_name(name)
            .unwrap()
    }

    #[test]
    fn each_row_gives_both_sides_one_secret_by_name_and_oid() {
        let algo = DefaultAlgoBuilder::default().build();
        for (name, params, dotted, encapsulation_bytes) in ROWS {
            let pair = pair(params);
            let by_oid = algo.kem().get_by_oid(&dotted.parse().unwrap()).unwrap();
            for kem in [kem(name), by_oid] {
                let (encapsulation, sent) = kem.encapsulate(pair.public()).unwrap();
                assert_eq!(encapsulation.len(), encapsulation_bytes, "{name}");
                assert_eq!(sent.as_bytes().len(), 32, "{name}");

                let received = kem.decapsulate(pair.private(), &encapsulation).unwrap();
                assert_eq!(sent.as_bytes(), received.as_bytes(), "{name}");
            }
        }
    }

    #[test]
    fn the_crate_underneath_decapsulates_what_the_row_encapsulates() {
        let params = MlKemParameters::ML_KEM_768;
        let pair = pair(params);
        let (encapsulation, sent) = kem("ML-KEM-768").encapsulate(pair.public()).unwrap();

        let private = pair.private().as_any().downcast_ref::<MlKemPrivateKey>();
        let mut decapsulator = MlKemDecapsulator::new(params);
        decapsulator.init(private.unwrap()).unwrap();
        let mut received = [0; 32];
        decapsulator
            .decapsulate(&encapsulation, &mut received)
            .unwrap();
        assert_eq!(sent.as_bytes(), received);
    }

    #[test]
    fn a_changed_encapsulation_gives_another_secret_and_no_error() {
        let pair = pair(MlKemParameters::ML_KEM_768);
        let kem = kem("ML-KEM-768");
        let (mut encapsulation, sent) = kem.encapsulate(pair.public()).unwrap();
        encapsulation[0] ^= 1;

        let received = kem.decapsulate(pair.private(), &encapsulation).unwrap();
        assert_ne!(sent.as_bytes(), received.as_bytes());
    }

    #[test]
    fn an_encapsulation_of_the_wrong_length_is_data_length() {
        let pair = pair(MlKemParameters::ML_KEM_768);
        let error = kem("ML-KEM-768")
            .decapsulate(pair.private(), &[0; 16])
            .err()
            .unwrap();
        assert_eq!(error.kind(), ErrorKind::DataLength);
    }

    #[test]
    fn keys_of_another_parameter_set_or_another_type_are_invalid_params() {
        let pair = pair(MlKemParameters::ML_KEM_512);
        let kem = kem("ML-KEM-768");

        let error = kem.encapsulate(pair.public()).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
        let error = kem.decapsulate(pair.private(), &[0; 1088]).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);

        let error = kem.encapsulate(&KeyLength::new(1)).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
        let error = kem.decapsulate(pair.public(), &[0; 1088]).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }

    #[test]
    fn the_case_of_a_name_does_not_matter() {
        let algo = DefaultAlgoBuilder::default().build();
        assert!(algo.kem().get_by_name("ml-kem-768").is_ok());
    }
}
