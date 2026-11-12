use tc_agreement::{Agreement, AgreementInit};
use tc_asn1::NamedOid;
use tc_bigint::PaddedBigUint;
use tc_digest::Digest;
use tc_ec_core::Curve;
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_ecvko::{EcVkoAgreement, EcVkoError, EcVkoParams};

use crate::agreement::dyn_agreement::DynAgreement;
use crate::agreement::{AgreementEntry, AgreementPeer, AnyAgreementParams};
use crate::need::Need;
use crate::params::ec_curves::with_ec_curves;
use crate::params::{AnyEcPrivateKey, AnyEcPublicKey, AnyPrivateKey, AnyPublicKey};
use crate::{AlgoError, ErrorKind};

// The OIDs live under CryptoPro's 1.2.643.2.2 and TC26's 1.2.643.7.1.1
#[cfg(feature = "gost3411")]
macro_rules! cryptopro {
    ($arc:literal, $dotted:literal, $name:literal) => {
        NamedOid::new(&[0x2a, 0x85, 0x03, 0x02, 0x02, $arc], $dotted, $name)
    };
}

macro_rules! tc26 {
    ($branch:literal, $arc:literal, $dotted:literal, $name:literal) => {
        NamedOid::new(
            &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, $branch, $arc],
            $dotted,
            $name,
        )
    };
}

// Bouncy Castle's ECVkoAgreement over GOST R 34.11-94, with GOST-3410-2001 as its alias and the
// OIDs of the GOST R 34.10-2001 key and of CryptoPro-ESDH. The UKM is required, as RFC 7836's VKO
// multiplies by it
#[cfg(feature = "gost3411")]
pub(super) const ECGOST3410: AgreementEntry = AgreementEntry::new(
    &["ECGOST3410", "GOST-3410-2001"],
    &[
        cryptopro!(0x13, "1.2.643.2.2.19", "id-GostR3410-2001"),
        cryptopro!(0x60, "1.2.643.2.2.96", "id-GostR3410-2001-CryptoPro-ESDH"),
    ],
    Need::Required,
    Need::Forbidden,
    || Box::new(EcVko::new(Hash::Gost3411)),
);

// Bouncy Castle's ECVkoAgreement over GOST R 34.11-2012's 256-bit hash, with the OIDs of the
// 2012 agreement and of the 256-bit key
pub(super) const ECGOST3410_2012_256: AgreementEntry = AgreementEntry::new(
    &["ECGOST3410-2012-256"],
    &[
        tc26!(
            0x06,
            0x01,
            "1.2.643.7.1.1.6.1",
            "id-tc26-agreement-gost-3410-12-256"
        ),
        tc26!(0x01, 0x01, "1.2.643.7.1.1.1.1", "id-tc26-gost3410-12-256"),
    ],
    Need::Required,
    Need::Forbidden,
    || Box::new(EcVko::new(Hash::Gost3411_2012_256)),
);

// Likewise over the 512-bit hash
pub(super) const ECGOST3410_2012_512: AgreementEntry = AgreementEntry::new(
    &["ECGOST3410-2012-512"],
    &[
        tc26!(
            0x06,
            0x02,
            "1.2.643.7.1.1.6.2",
            "id-tc26-agreement-gost-3410-12-512"
        ),
        tc26!(0x01, 0x02, "1.2.643.7.1.1.1.2", "id-tc26-gost3410-12-512"),
    ],
    Need::Required,
    Need::Forbidden,
    || Box::new(EcVko::new(Hash::Gost3411_2012_512)),
);

// The digest that hashes the shared point; the secret is as long as its output
#[derive(Clone, Copy)]
enum Hash {
    #[cfg(feature = "gost3411")]
    Gost3411,
    Gost3411_2012_256,
    Gost3411_2012_512,
}

impl Hash {
    fn size(self) -> usize {
        match self {
            #[cfg(feature = "gost3411")]
            Self::Gost3411 => 32,
            Self::Gost3411_2012_256 => 32,
            Self::Gost3411_2012_512 => 64,
        }
    }
}

// tc_ecvko's agreement is generic over the curve and the digest, so this keeps the key and the
// UKM and picks the agreement for the curve when calculating
struct EcVko {
    hash: Hash,
    // The key and the UKM, once init has succeeded
    key: Option<(AnyEcPrivateKey, Vec<u8>)>,
}

impl EcVko {
    fn new(hash: Hash) -> Self {
        Self { hash, key: None }
    }
}

impl DynAgreement for EcVko {
    fn init(&mut self, params: &AnyAgreementParams) -> Result<(), AlgoError> {
        self.key = None;
        let (AnyPrivateKey::Ec(key), Some(ukm)) = (params.key(), params.ukm()) else {
            return Err(AlgoError::new(ErrorKind::InvalidParams));
        };
        self.key = Some((key.clone(), ukm.to_vec()));
        Ok(())
    }

    fn agreement_size(&self) -> Option<usize> {
        self.key.as_ref().map(|_| self.hash.size())
    }

    fn calculate_agreement(
        &self,
        peer: &AgreementPeer,
        output: &mut [u8],
    ) -> Result<(), AlgoError> {
        let (key, ukm) = self
            .key
            .as_ref()
            .ok_or(AlgoError::new(ErrorKind::NotInitialized))?;
        let public_key = match peer.key() {
            AnyPublicKey::Ec(key) => key,
            #[allow(unreachable_patterns, reason = "every other variant may be off")]
            _ => return Err(AlgoError::new(ErrorKind::InvalidParams)),
        };
        agree(self.hash, key, ukm, public_key, output)
    }
}

macro_rules! dispatch {
    ($($(#[$cfg:meta])* $curve:ident => $generator:ident,)*) => {
        // A public key on another curve than the private key's is refused here
        fn agree(
            hash: Hash,
            key: &AnyEcPrivateKey,
            ukm: &[u8],
            public_key: &AnyEcPublicKey,
            output: &mut [u8],
        ) -> Result<(), AlgoError> {
            match (key, public_key) {
                $(
                    $(#[$cfg])*
                    (AnyEcPrivateKey::$curve(key), AnyEcPublicKey::$curve(public_key)) => {
                        agree_on(hash, key, ukm, public_key, output)
                    }
                )*
                _ => Err(AlgoError::new(ErrorKind::InvalidParams)),
            }
        }
    };
}

with_ec_curves!(dispatch);

fn agree_on<C: Curve<Scalar = PaddedBigUint>>(
    hash: Hash,
    key: &EcPrivateKey<C>,
    ukm: &[u8],
    public_key: &EcPublicKey<C>,
    output: &mut [u8],
) -> Result<(), AlgoError> {
    let params = EcVkoParams::new(key.clone(), ukm.to_vec());
    match hash {
        #[cfg(feature = "gost3411")]
        Hash::Gost3411 => run(
            tc_gost3411::Gost3411Digest::new(),
            &params,
            public_key,
            output,
        ),
        Hash::Gost3411_2012_256 => run(
            tc_gost3411::Gost3411_2012_256Digest::new(),
            &params,
            public_key,
            output,
        ),
        Hash::Gost3411_2012_512 => run(
            tc_gost3411::Gost3411_2012_512Digest::new(),
            &params,
            public_key,
            output,
        ),
    }
}

fn run<C: Curve<Scalar = PaddedBigUint>, D: Digest + Clone>(
    digest: D,
    params: &EcVkoParams<C>,
    public_key: &EcPublicKey<C>,
    output: &mut [u8],
) -> Result<(), AlgoError> {
    let mut agreement = EcVkoAgreement::new(digest);
    agreement.init(params).map_err(error)?;
    agreement
        .calculate_agreement(public_key, output)
        .map_err(error)
}

// A public key of another domain, not on the curve or at infinity, and a shared point at
// infinity, as a UKM of zero gives, all come from the keys, so all are InvalidParams
fn error(error: EcVkoError) -> AlgoError {
    let kind = match error {
        EcVkoError::NotInitialized => ErrorKind::NotInitialized,
        EcVkoError::BufferTooSmall => ErrorKind::DataLength,
        _ => ErrorKind::InvalidParams,
    };
    AlgoError::with_source(kind, error)
}
