use tc_agreement::{Agreement, AgreementInit};
use tc_bigint::PaddedBigUint;
use tc_ec_core::{Curve, FieldElement, Point};
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_ecdh_v2::{EcdhBasicAgreement, EcdhError, EcdhcBasicAgreement};

use crate::agreement::dyn_agreement::DynAgreement;
use crate::agreement::{AgreementEntry, AgreementPeer, AnyAgreementParams};
use crate::need::Need;
use crate::params::ec_curves::with_ec_curves;
use crate::params::{AnyEcPrivateKey, AnyEcPublicKey, AnyPrivateKey, AnyPublicKey};
use crate::{AlgoError, ErrorKind};

// Bouncy Castle's ECDHBasicAgreement, IEEE P1363's ECSVDP-DH. Bouncy Castle gives it no OID: the
// ECDH OIDs name the schemes with a KDF
pub(super) const ECDH: AgreementEntry = AgreementEntry::new(
    &["ECDH"],
    &[],
    Need::Forbidden,
    Need::Forbidden,
    || Box::new(Ecdh::new(false)),
);

// Bouncy Castle's ECDHCBasicAgreement, ECSVDP-DHC, with ECCDH as its alias. It multiplies by the
// cofactor too, so on a curve whose cofactor is not 1 its secret differs from ECDH's
pub(super) const ECDHC: AgreementEntry = AgreementEntry::new(
    &["ECDHC", "ECCDH"],
    &[],
    Need::Forbidden,
    Need::Forbidden,
    || Box::new(Ecdh::new(true)),
);

// The agreements of tc_ecdh_v2 are generic over the curve, so this keeps the key, whose curve is
// its variant, and picks the agreement for the curve when calculating
struct Ecdh {
    cofactor: bool,
    // The key and the length of a coordinate of its curve in bytes, once init has succeeded
    key: Option<(AnyEcPrivateKey, usize)>,
}

impl Ecdh {
    fn new(cofactor: bool) -> Self {
        Self {
            cofactor,
            key: None,
        }
    }
}

impl DynAgreement for Ecdh {
    fn init(&mut self, params: &AnyAgreementParams) -> Result<(), AlgoError> {
        self.key = None;
        let key = match params.key() {
            AnyPrivateKey::Ec(key) => key,
            #[allow(unreachable_patterns, reason = "every other variant may be off")]
            _ => return Err(AlgoError::new(ErrorKind::InvalidParams)),
        };
        self.key = Some((key.clone(), field_size(key)));
        Ok(())
    }

    fn agreement_size(&self) -> Option<usize> {
        self.key.as_ref().map(|(_, size)| *size)
    }

    fn calculate_agreement(
        &self,
        peer: &AgreementPeer,
        output: &mut [u8],
    ) -> Result<(), AlgoError> {
        let (key, _) = self
            .key
            .as_ref()
            .ok_or(AlgoError::new(ErrorKind::NotInitialized))?;
        let public_key = match peer.key() {
            AnyPublicKey::Ec(key) => key,
            #[allow(unreachable_patterns, reason = "every other variant may be off")]
            _ => return Err(AlgoError::new(ErrorKind::InvalidParams)),
        };
        agree(self.cofactor, key, public_key, output)
    }
}

macro_rules! dispatch {
    ($($(#[$cfg:meta])* $curve:ident => $generator:ident,)*) => {
        fn field_size(key: &AnyEcPrivateKey) -> usize {
            match key {
                $($(#[$cfg])* AnyEcPrivateKey::$curve(key) => field_size_on(key),)*
            }
        }

        // A public key on another curve than the private key's is refused here, before either
        // agreement sees it
        fn agree(
            cofactor: bool,
            key: &AnyEcPrivateKey,
            public_key: &AnyEcPublicKey,
            output: &mut [u8],
        ) -> Result<(), AlgoError> {
            match (key, public_key) {
                $(
                    $(#[$cfg])*
                    (AnyEcPrivateKey::$curve(key), AnyEcPublicKey::$curve(public_key)) => {
                        agree_on(cofactor, key, public_key, output)
                    }
                )*
                _ => Err(AlgoError::new(ErrorKind::InvalidParams)),
            }
        }
    };
}

with_ec_curves!(dispatch);

// Bouncy Castle's GetFieldSize, as both agreements give it
fn field_size_on<C: Curve<Scalar = PaddedBigUint>>(key: &EcPrivateKey<C>) -> usize {
    key.g().curve().one().encoded_length()
}

fn agree_on<C: Curve<Scalar = PaddedBigUint>>(
    cofactor: bool,
    key: &EcPrivateKey<C>,
    public_key: &EcPublicKey<C>,
    output: &mut [u8],
) -> Result<(), AlgoError> {
    if cofactor {
        let mut agreement = EcdhcBasicAgreement::new();
        agreement.init(key).map_err(error)?;
        agreement
            .calculate_agreement(public_key, output)
            .map_err(error)
    } else {
        let mut agreement = EcdhBasicAgreement::new();
        agreement.init(key).map_err(error)?;
        agreement
            .calculate_agreement(public_key, output)
            .map_err(error)
    }
}

// A public key not on the curve or at infinity, and a shared point at infinity, all come from the
// keys, so all are InvalidParams
fn error(error: EcdhError) -> AlgoError {
    let kind = match error {
        EcdhError::NotInitialized => ErrorKind::NotInitialized,
        EcdhError::BufferTooSmall => ErrorKind::DataLength,
        _ => ErrorKind::InvalidParams,
    };
    AlgoError::with_source(kind, error)
}
