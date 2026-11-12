use tc_agreement::{Agreement, AgreementInit};
use tc_bigint::PaddedBigUint;
use tc_ec_core::{Curve, FieldElement, Point};
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_ecmqv::{EcMqvBasicAgreement, EcMqvError, MqvPrivateParams, MqvPublicParams};

use crate::agreement::dyn_agreement::DynAgreement;
use crate::agreement::{AgreementEntry, AgreementPeer, AnyAgreementParams};
use crate::need::Need;
use crate::params::ec_curves::with_ec_curves;
use crate::params::{AnyEcPrivateKey, AnyEcPublicKey, AnyPrivateKey, AnyPublicKey};
use crate::{AlgoError, ErrorKind};

// Bouncy Castle's ECMqvBasicAgreement, ECMQV of SEC 1. It takes a static and an ephemeral key of
// each party, so both are required. Bouncy Castle gives it no OID: the MQV OIDs name the schemes
// with a KDF
pub(super) const ECMQV: AgreementEntry = AgreementEntry::new(
    &["ECMQV"],
    &[],
    Need::Forbidden,
    Need::Required,
    || Box::new(EcMqv::default()),
);

// tc_ecmqv's agreement is generic over the curve, so this keeps the keys, whose curve is their
// variant, and picks the agreement for the curve when calculating
#[derive(Default)]
struct EcMqv {
    // The static and the ephemeral key, and the length of a coordinate of their curve in bytes,
    // once init has succeeded
    keys: Option<(AnyEcPrivateKey, AnyEcPrivateKey, usize)>,
}

impl DynAgreement for EcMqv {
    fn init(&mut self, params: &AnyAgreementParams) -> Result<(), AlgoError> {
        self.keys = None;
        let (AnyPrivateKey::Ec(key), Some(AnyPrivateKey::Ec(ephemeral))) =
            (params.key(), params.ephemeral())
        else {
            return Err(AlgoError::new(ErrorKind::InvalidParams));
        };
        let size = field_size(key, ephemeral)?;
        self.keys = Some((key.clone(), ephemeral.clone(), size));
        Ok(())
    }

    fn agreement_size(&self) -> Option<usize> {
        self.keys.as_ref().map(|(_, _, size)| *size)
    }

    fn calculate_agreement(
        &self,
        peer: &AgreementPeer,
        output: &mut [u8],
    ) -> Result<(), AlgoError> {
        let (key, ephemeral, _) = self
            .keys
            .as_ref()
            .ok_or(AlgoError::new(ErrorKind::NotInitialized))?;
        let (AnyPublicKey::Ec(peer_key), Some(AnyPublicKey::Ec(peer_ephemeral))) =
            (peer.key(), peer.ephemeral())
        else {
            return Err(AlgoError::new(ErrorKind::InvalidParams));
        };
        agree(key, ephemeral, peer_key, peer_ephemeral, output)
    }
}

macro_rules! dispatch {
    ($($(#[$cfg:meta])* $curve:ident => $generator:ident,)*) => {
        // Both of this party's keys on one curve, or InvalidParams
        fn field_size(key: &AnyEcPrivateKey, ephemeral: &AnyEcPrivateKey) -> Result<usize, AlgoError> {
            match (key, ephemeral) {
                $(
                    $(#[$cfg])*
                    (AnyEcPrivateKey::$curve(key), AnyEcPrivateKey::$curve(_)) => {
                        Ok(field_size_on(key))
                    }
                )*
                _ => Err(AlgoError::new(ErrorKind::InvalidParams)),
            }
        }

        // All four keys on one curve, or InvalidParams
        fn agree(
            key: &AnyEcPrivateKey,
            ephemeral: &AnyEcPrivateKey,
            peer_key: &AnyEcPublicKey,
            peer_ephemeral: &AnyEcPublicKey,
            output: &mut [u8],
        ) -> Result<(), AlgoError> {
            match (key, ephemeral, peer_key, peer_ephemeral) {
                $(
                    $(#[$cfg])*
                    (
                        AnyEcPrivateKey::$curve(key),
                        AnyEcPrivateKey::$curve(ephemeral),
                        AnyEcPublicKey::$curve(peer_key),
                        AnyEcPublicKey::$curve(peer_ephemeral),
                    ) => agree_on(key, ephemeral, peer_key, peer_ephemeral, output),
                )*
                _ => Err(AlgoError::new(ErrorKind::InvalidParams)),
            }
        }
    };
}

with_ec_curves!(dispatch);

// Bouncy Castle's GetFieldSize
fn field_size_on<C: Curve<Scalar = PaddedBigUint>>(key: &EcPrivateKey<C>) -> usize {
    key.g().curve().one().encoded_length()
}

// The agreement computes this party's ephemeral public key from its private key in init
fn agree_on<C: Curve<Scalar = PaddedBigUint>>(
    key: &EcPrivateKey<C>,
    ephemeral: &EcPrivateKey<C>,
    peer_key: &EcPublicKey<C>,
    peer_ephemeral: &EcPublicKey<C>,
    output: &mut [u8],
) -> Result<(), AlgoError> {
    let mut agreement = EcMqvBasicAgreement::new();
    agreement
        .init(&MqvPrivateParams::new(key.clone(), ephemeral.clone()))
        .map_err(error)?;
    let peer = MqvPublicParams::new(peer_key.clone(), peer_ephemeral.clone());
    agreement
        .calculate_agreement(&peer, output)
        .map_err(error)
}

// Keys of another domain, a public key not on the curve or at infinity, and a shared point at
// infinity all come from the keys, so all are InvalidParams
fn error(error: EcMqvError) -> AlgoError {
    let kind = match error {
        EcMqvError::NotInitialized => ErrorKind::NotInitialized,
        EcMqvError::BufferTooSmall => ErrorKind::DataLength,
        _ => ErrorKind::InvalidParams,
    };
    AlgoError::with_source(kind, error)
}
