use tc_agreement::{Agreement as _, AgreementInit};
use tc_dh::{DhAgreementError, DhBasicAgreement};
use tc_dh_key::{DhPrivateKey, DhPublicKey};

use crate::agreement::{Agreement, AgreementEntry};
use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind, Params};

// The row of DH, to give to DefaultAlgoBuilder::reg_agreement. Its name and alias are those of
// Bouncy Castle's AgreementUtilities, which gives it no OID
pub(super) fn dh(_context: &DefaultAlgoContext) -> Vec<Box<dyn AgreementEntry>> {
    vec![Box::new(Row {
        aliases: vec!["DIFFIEHELLMAN".to_string()],
    })]
}

struct Row {
    aliases: Vec<String>,
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        "DH"
    }

    fn aliases(&self) -> &[String] {
        &self.aliases
    }
}

impl AgreementEntry for Row {
    fn create(&self) -> Box<dyn Agreement> {
        Box::new(Dh {
            agreement: DhBasicAgreement::new(),
            size: None,
        })
    }
}

// Its params are a DhPrivateKey, and the other side's key a DhPublicKey
struct Dh {
    agreement: DhBasicAgreement,
    // The length of p in bytes, once init has succeeded, since asking the engine sooner panics
    size: Option<usize>,
}

impl tc_agreement::Agreement for Dh {
    type PublicKey = dyn Params;
    type Error = AlgoError;

    // The length of p in bytes, or 0 before init
    fn agreement_size(&self) -> usize {
        self.size.unwrap_or(0)
    }

    fn calculate_agreement(
        &self,
        public_key: &dyn Params,
        output: &mut [u8],
    ) -> Result<(), AlgoError> {
        self.size.ok_or(AlgoError::new(ErrorKind::NotInitialized))?;
        let public_key = public_key
            .as_any()
            .downcast_ref::<DhPublicKey>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        self.agreement
            .calculate_agreement(public_key, output)
            .map_err(algo_error)
    }
}

impl AgreementInit<dyn Params> for Dh {
    type Error = AlgoError;

    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError> {
        self.size = None;
        let key = params
            .as_any()
            .downcast_ref::<DhPrivateKey>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        self.agreement.init(key).map_err(algo_error)?;
        self.size = Some(self.agreement.agreement_size());
        Ok(())
    }
}

impl Agreement for Dh {}

// A bad group, a public key of another group or outside the subgroup, and a shared secret of 1 all
// come from the keys, so all are InvalidParams
fn algo_error(error: DhAgreementError) -> AlgoError {
    let kind = match error {
        DhAgreementError::NotInitialized | DhAgreementError::MessageNotCalculated => {
            ErrorKind::NotInitialized
        }
        DhAgreementError::BufferTooSmall => ErrorKind::DataLength,
        _ => ErrorKind::InvalidParams,
    };
    AlgoError::with_source(kind, error)
}

#[cfg(test)]
mod tests {
    use rand::rngs::SysRng;
    use rand_core::UnwrapErr;
    use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
    use tc_bigint::PaddedBigUint;
    use tc_dh_key::standard_groups::{rfc3526_2048, rfc3526_3072};
    use tc_dh_key::{
        DhKeyGenerationParams, DhKeyPairGenerator, DhParameters, DhPrivateKey, DhPublicKey,
    };

    use crate::agreement::Agreement;
    use crate::params::KeyLength;
    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind};

    const NAME: &str = "DH";

    fn pair(group: DhParameters) -> (DhPublicKey, DhPrivateKey) {
        let mut rng = UnwrapErr(SysRng);
        let mut generator = DhKeyPairGenerator::new();
        generator
            .init(DhKeyGenerationParams::new(group, &mut rng))
            .unwrap();
        generator.generate_key_pair().unwrap()
    }

    fn agreement(private: &DhPrivateKey) -> Box<dyn Agreement> {
        let algo = DefaultAlgoBuilder::default().build();
        let mut agreement = algo.agreement().get_by_name(NAME).unwrap();
        agreement.init(private).unwrap();
        agreement
    }

    #[test]
    fn both_sides_calculate_the_same_secret_of_the_length_of_p() {
        let (alice_public, alice_private) = pair(rfc3526_2048());
        let (bob_public, bob_private) = pair(rfc3526_2048());

        let alice = agreement(&alice_private)
            .calculate_shared_secret(&bob_public)
            .unwrap();
        let bob = agreement(&bob_private)
            .calculate_shared_secret(&alice_public)
            .unwrap();

        assert_eq!(alice.as_bytes(), bob.as_bytes());
        assert_eq!(alice.as_bytes().len(), 256);
    }

    #[test]
    fn the_row_is_found_by_its_alias_whatever_the_case() {
        let algo = DefaultAlgoBuilder::default().build();
        assert!(algo.agreement().get_by_name("DiffieHellman").is_ok());
        assert!(algo.agreement().get_by_name("dh").is_ok());
    }

    #[test]
    fn calculating_needs_an_init_that_succeeded() {
        let (public, _) = pair(rfc3526_2048());
        let algo = DefaultAlgoBuilder::default().build();
        let mut agreement = algo.agreement().get_by_name(NAME).unwrap();

        let error = agreement.calculate_shared_secret(&public).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);

        assert!(agreement.init(&KeyLength::new(1)).is_err());
        let error = agreement.calculate_shared_secret(&public).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
    }

    #[test]
    fn init_and_calculating_refuse_params_of_another_type() {
        let (_, private) = pair(rfc3526_2048());
        let algo = DefaultAlgoBuilder::default().build();
        let mut uninitialized = algo.agreement().get_by_name(NAME).unwrap();
        let error = uninitialized.init(&KeyLength::new(1)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);

        let error = agreement(&private)
            .calculate_shared_secret(&KeyLength::new(1))
            .err()
            .unwrap();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }

    #[test]
    fn a_public_key_of_another_group_or_of_a_weak_value_is_invalid_params() {
        let (_, private) = pair(rfc3526_2048());
        let agreement = agreement(&private);

        let (other_group, _) = pair(rfc3526_3072());
        let error = agreement.calculate_shared_secret(&other_group).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);

        let one = DhPublicKey::new(PaddedBigUint::from(1u8), rfc3526_2048());
        let error = agreement.calculate_shared_secret(&one).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}
