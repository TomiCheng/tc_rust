use rand_core::CryptoRng;
use tc_asn1::Asn1Oid;
use tc_kem::{KemDecapsulator, KemEncapsulator, KemInit};
use tc_ml_kem::{
    MlKemDecapsulator, MlKemEncapsulator, MlKemError, MlKemParameters, MlKemPrivateKey,
    MlKemPublicKey,
};

use crate::kem::{Decapsulator, Encapsulator, KemEntry};
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
    fn create_encapsulator(&self) -> Box<dyn Encapsulator> {
        Box::new(MlKemEncapsulate(MlKemEncapsulator::new(
            self.params,
            (self.rand)(),
        )))
    }

    fn create_decapsulator(&self) -> Box<dyn Decapsulator> {
        Box::new(MlKemDecapsulate(MlKemDecapsulator::new(self.params)))
    }
}

// Keyed by an MlKemPublicKey of the row's parameter set, drawing from the builder's source
struct MlKemEncapsulate(MlKemEncapsulator<Box<dyn CryptoRng>>);

impl KemEncapsulator for MlKemEncapsulate {
    type Error = AlgoError;

    fn encapsulation_length(&self) -> usize {
        self.0.encapsulation_length()
    }

    fn secret_length(&self) -> usize {
        self.0.secret_length()
    }

    fn encapsulate(
        &mut self,
        encapsulation: &mut [u8],
        secret: &mut [u8],
    ) -> Result<(), AlgoError> {
        self.0
            .encapsulate(encapsulation, secret)
            .map_err(algo_error)
    }
}

impl KemInit<dyn Params> for MlKemEncapsulate {
    type Error = AlgoError;

    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError> {
        let key = params
            .as_any()
            .downcast_ref::<MlKemPublicKey>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        self.0.init(key).map_err(algo_error)
    }
}

impl Encapsulator for MlKemEncapsulate {}

// Keyed by an MlKemPrivateKey of the row's parameter set
struct MlKemDecapsulate(MlKemDecapsulator);

impl KemDecapsulator for MlKemDecapsulate {
    type Error = AlgoError;

    fn encapsulation_length(&self) -> usize {
        self.0.encapsulation_length()
    }

    fn secret_length(&self) -> usize {
        self.0.secret_length()
    }

    fn decapsulate(&mut self, encapsulation: &[u8], secret: &mut [u8]) -> Result<(), AlgoError> {
        self.0
            .decapsulate(encapsulation, secret)
            .map_err(algo_error)
    }
}

impl KemInit<dyn Params> for MlKemDecapsulate {
    type Error = AlgoError;

    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError> {
        let key = params
            .as_any()
            .downcast_ref::<MlKemPrivateKey>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        self.0.init(key).map_err(algo_error)
    }
}

impl Decapsulator for MlKemDecapsulate {}

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

    #[test]
    fn each_row_gives_both_sides_one_secret_by_name_and_oid() {
        let algo = DefaultAlgoBuilder::default().build();
        for (name, params, dotted, encapsulation_bytes) in ROWS {
            let pair = pair(params);
            let oid = dotted.parse().unwrap();

            let (encapsulation, sent) =
                algo.kem().encapsulate_by_name(name, pair.public()).unwrap();
            assert_eq!(encapsulation.len(), encapsulation_bytes, "{name}");
            assert_eq!(sent.len(), 32, "{name}");
            let received = algo
                .kem()
                .decapsulate_by_oid(&oid, pair.private(), &encapsulation)
                .unwrap();
            assert_eq!(sent, received, "{name}");

            let (encapsulation, sent) = algo.kem().encapsulate_by_oid(&oid, pair.public()).unwrap();
            let received = algo
                .kem()
                .decapsulate_by_name(name, pair.private(), &encapsulation)
                .unwrap();
            assert_eq!(sent, received, "{name}");
        }
    }

    #[test]
    fn the_encapsulator_and_decapsulator_give_their_lengths_and_work_in_buffers() {
        let algo = DefaultAlgoBuilder::default().build();
        let pair = pair(MlKemParameters::ML_KEM_768);

        let mut encapsulator = algo.kem().get_encapsulator_by_name("ML-KEM-768").unwrap();
        encapsulator.init(pair.public()).unwrap();
        assert_eq!(encapsulator.encapsulation_length(), 1088);
        assert_eq!(encapsulator.secret_length(), 32);
        let mut encapsulation = [0; 1088];
        let mut sent = [0; 32];
        encapsulator
            .encapsulate(&mut encapsulation, &mut sent)
            .unwrap();

        let mut decapsulator = algo.kem().get_decapsulator_by_name("ML-KEM-768").unwrap();
        decapsulator.init(pair.private()).unwrap();
        let mut received = [0; 32];
        decapsulator
            .decapsulate(&encapsulation, &mut received)
            .unwrap();
        assert_eq!(sent, received);
    }

    #[test]
    fn the_crate_underneath_decapsulates_what_the_row_encapsulates() {
        let params = MlKemParameters::ML_KEM_768;
        let pair = pair(params);
        let algo = DefaultAlgoBuilder::default().build();
        let (encapsulation, sent) = algo
            .kem()
            .encapsulate_by_name("ML-KEM-768", pair.public())
            .unwrap();

        let private = pair.private().as_any().downcast_ref::<MlKemPrivateKey>();
        let mut decapsulator = MlKemDecapsulator::new(params);
        decapsulator.init(private.unwrap()).unwrap();
        let mut received = [0; 32];
        decapsulator
            .decapsulate(&encapsulation, &mut received)
            .unwrap();
        assert_eq!(sent, received);
    }

    #[test]
    fn a_changed_encapsulation_gives_another_secret_and_no_error() {
        let pair = pair(MlKemParameters::ML_KEM_768);
        let algo = DefaultAlgoBuilder::default().build();
        let (mut encapsulation, sent) = algo
            .kem()
            .encapsulate_by_name("ML-KEM-768", pair.public())
            .unwrap();
        encapsulation[0] ^= 1;

        let received = algo
            .kem()
            .decapsulate_by_name("ML-KEM-768", pair.private(), &encapsulation)
            .unwrap();
        assert_ne!(sent, received);
    }

    #[test]
    fn an_encapsulation_of_the_wrong_length_is_data_length() {
        let pair = pair(MlKemParameters::ML_KEM_768);
        let algo = DefaultAlgoBuilder::default().build();
        let error = algo
            .kem()
            .decapsulate_by_name("ML-KEM-768", pair.private(), &[0; 16])
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DataLength);
    }

    #[test]
    fn keys_of_another_parameter_set_or_another_type_are_invalid_params() {
        let pair = pair(MlKemParameters::ML_KEM_512);
        let algo = DefaultAlgoBuilder::default().build();
        let kem = algo.kem();
        let name = "ML-KEM-768";

        let error = kem.encapsulate_by_name(name, pair.public()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
        let error = kem
            .decapsulate_by_name(name, pair.private(), &[0; 1088])
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);

        let error = kem
            .encapsulate_by_name(name, &KeyLength::new(1))
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
        let error = kem
            .decapsulate_by_name(name, pair.public(), &[0; 1088])
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }

    #[test]
    fn encapsulating_before_init_is_not_initialized() {
        let algo = DefaultAlgoBuilder::default().build();
        let mut encapsulator = algo.kem().get_encapsulator_by_name("ML-KEM-768").unwrap();
        let error = encapsulator
            .encapsulate(&mut [0; 1088], &mut [0; 32])
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
    }

    #[test]
    fn the_case_of_a_name_does_not_matter() {
        let algo = DefaultAlgoBuilder::default().build();
        assert!(algo.kem().get_encapsulator_by_name("ml-kem-768").is_ok());
        assert!(algo.kem().get_decapsulator_by_name("ml-kem-768").is_ok());
    }
}
