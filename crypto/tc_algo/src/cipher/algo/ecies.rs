use core::error::Error;

use tc_agreement::{Agreement, AgreementInit};
use tc_asn1::Asn1Oid;
use tc_bigint::PaddedBigUint;
use tc_ec_core::Curve;
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_ecdh_v2::EcdhBasicAgreement;
use tc_ies::{IesEngine, IesError, IesParamsRef};
use tc_kdf::kdf::Kdf2;
use tc_macs::Hmac;
use tc_sha::Sha1Digest;

use super::ies::{Ies, IesInit};
use crate::cipher::{Cipher, CipherDirection, CipherEntry};
use crate::params::cipher::IesEcParams;
use crate::params::ec_curves::ct_curves;
use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind, Params};

// The row of ECIES, to give to DefaultAlgoBuilder::reg_cipher. Its name and parts are those of
// Bouncy Castle's CipherUtilities: IES with ECDH for the agreement. As there, the curve comes from
// the keys: the row takes an IesEcParams over any of the constant-time curve types, and builds the
// engine of that curve when it is initialized
pub(super) fn ecies(_context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![Box::new(Row)]
}

struct Row;

impl EntryBase for Row {
    fn name(&self) -> &str {
        "ECIES"
    }

    fn oids(&self) -> &[Asn1Oid] {
        &[]
    }
}

impl CipherEntry for Row {
    fn create(&self) -> Box<dyn Cipher> {
        Box::new(Ies::new(EcIes(None)))
    }
}

// The engine of the curve of the last init; the agreement is behind it, so only the messages remain
trait Process {
    fn process_block(&mut self, input: &[u8]) -> Result<Vec<u8>, IesError>;
}

impl<A> Process for IesEngine<A, Kdf2<Sha1Digest>, Hmac<Sha1Digest>> {
    fn process_block(&mut self, input: &[u8]) -> Result<Vec<u8>, IesError> {
        IesEngine::process_block(self, input)
    }
}

struct EcIes(Option<Box<dyn Process>>);

type Try = fn(CipherDirection, &IesEcParams) -> Option<Result<Box<dyn Process>, AlgoError>>;

// The curve types the row takes, those of the EC keys
const CURVES: &[Try] = ct_curves!(engine);

// The engine over the curve C, initialized, when the private key is on C; None when it is not
fn engine<C>(
    direction: CipherDirection,
    params: &IesEcParams,
) -> Option<Result<Box<dyn Process>, AlgoError>>
where
    C: Curve<Scalar = PaddedBigUint> + 'static,
    EcdhBasicAgreement<C>: Agreement<PublicKey = EcPublicKey<C>> + AgreementInit<EcPrivateKey<C>>,
    <EcdhBasicAgreement<C> as Agreement>::Error: Error + Send + Sync + 'static,
    <EcdhBasicAgreement<C> as AgreementInit<EcPrivateKey<C>>>::Error: Error + Send + Sync + 'static,
{
    let private_key = params
        .private_key()
        .as_any()
        .downcast_ref::<EcPrivateKey<C>>()?;
    // A public key on another curve, or of another type
    let Some(public_key) = params
        .public_key()
        .as_any()
        .downcast_ref::<EcPublicKey<C>>()
    else {
        return Some(Err(AlgoError::new(ErrorKind::InvalidParams)));
    };
    let mut engine = IesEngine::new(
        EcdhBasicAgreement::<C>::new(),
        Kdf2::new(Sha1Digest::new()),
        Hmac::new(Sha1Digest::new()),
    );
    let result = engine.init(
        direction.into(),
        private_key,
        public_key,
        &IesParamsRef::new(
            params.derivation_v(),
            params.encoding_v(),
            params.mac_key_bits(),
        ),
    );
    Some(
        result
            .map(|()| Box::new(engine) as Box<dyn Process>)
            .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error)),
    )
}

impl IesInit for EcIes {
    fn init(&mut self, direction: CipherDirection, params: &dyn Params) -> Result<(), AlgoError> {
        self.0 = None;
        let params = params
            .as_any()
            .downcast_ref::<IesEcParams>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        let engine = CURVES
            .iter()
            .find_map(|engine| engine(direction, params))
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))??;
        self.0 = Some(engine);
        Ok(())
    }

    fn process_block(&mut self, input: &[u8]) -> Result<Vec<u8>, IesError> {
        self.0
            .as_mut()
            .ok_or(IesError::NotInitialised)?
            .process_block(input)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use tc_asn1::Asn1Oid;
    use tc_bigint::{ArrayEncoding, PaddedBigUint};
    use tc_ec_key::{EcPrivateKey, EcPublicKey};
    use tc_fp_custom::named_curves::SECP192R1;
    use tc_fp_custom::{SecP192R1FieldElement, SecPCtCurve};

    use crate::generate::KeyPair;
    use crate::params::{cipher::IesEcParams, generate::EcKeyGenParams};
    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind, Params};

    type Secp192r1 = &'static SecPCtCurve<SecP192R1FieldElement>;
    static SECP192R1_CURVE: LazyLock<SecPCtCurve<SecP192R1FieldElement>> =
        LazyLock::new(|| SECP192R1.ct_curve());

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn params(private_key: Box<dyn Params>, public_key: Box<dyn Params>) -> IesEcParams {
        IesEcParams::new(
            private_key,
            public_key,
            vec![1, 2, 3, 4, 5, 6, 7, 8],
            vec![8, 7, 6, 5, 4, 3, 2, 1],
            64,
        )
    }

    fn pairs(curve: &EcKeyGenParams) -> (KeyPair, KeyPair) {
        let algo = DefaultAlgoBuilder::default().build();
        let generators = algo.key_pair_generator();
        (
            generators.generate_by_name_with("EC", curve).unwrap(),
            generators.generate_by_name_with("ECIES", curve).unwrap(),
        )
    }

    // Each side puts its own private key with the other's public key; both reach the same Z
    fn round_trip(curve: &EcKeyGenParams) {
        let (alice, bob) = pairs(curve);
        let (alice_public, alice_private) = alice.into_parts();
        let (bob_public, bob_private) = bob.into_parts();
        let algo = DefaultAlgoBuilder::default().build();
        let message = b"a message of no particular length";
        let sealed = algo
            .cipher()
            .encrypt_by_name("ECIES", &params(alice_private, bob_public), message)
            .unwrap();
        assert_eq!(sealed.len(), message.len() + 20);
        let opened = algo
            .cipher()
            .decrypt_by_name("ecies", &params(bob_private, alice_public), &sealed)
            .unwrap();
        assert_eq!(opened, message);
    }

    // The vector of Bouncy Castle's ECIESTest on secp192r1, as tc_ies tests it, through the row
    #[test]
    fn the_row_gives_bouncy_castles_vector_on_secp192r1() {
        let curve: Secp192r1 = &SECP192R1_CURVE;
        let g = SECP192R1.ct_generator(curve);
        let d = <PaddedBigUint as ArrayEncoding<u8>>::from_be(&hex(
            "1a8d598fc15bf0fd89030b5cb1111aeb92ae8baf5ea475fb",
        ))
        .unwrap();
        let q = curve
            .decode_point(&hex("0262b12d60690cdcf330babab6e69763b471f994dd702d16a5"))
            .unwrap();
        let private_key = EcPrivateKey::<Secp192r1>::new(g.clone(), d).unwrap();
        let public_key = EcPublicKey::<Secp192r1>::new(g, &q).unwrap();
        let params = params(Box::new(private_key), Box::new(public_key));

        let algo = DefaultAlgoBuilder::default().build();
        let sealed = algo
            .cipher()
            .encrypt_by_name("ECIES", &params, &hex("1234567890abcdef"))
            .unwrap();
        assert_eq!(
            sealed,
            hex("609ae8fe2727572da30a1d04e3dd0530de24ee89e7313f6c400992a6")
        );
        let opened = algo
            .cipher()
            .decrypt_by_name("ECIES", &params, &sealed)
            .unwrap();
        assert_eq!(opened, hex("1234567890abcdef"));
    }

    // One row takes the keys of the EC generator on a curve of each kind: a special prime curve,
    // a generic one, a special binary one, a generic one, and those of SM2 and DSTU 4145
    #[test]
    fn the_row_takes_keys_of_the_ec_generator_on_every_kind_of_curve() {
        for curve in [
            EcKeyGenParams::new("P-256"),
            EcKeyGenParams::new("brainpoolP256r1"),
            EcKeyGenParams::new("sect233k1"),
            EcKeyGenParams::new("c2pnb163v1"),
            EcKeyGenParams::new("sm2p256v1"),
            EcKeyGenParams::from_oid("1.3.132.0.34".parse::<Asn1Oid>().unwrap()),
            EcKeyGenParams::from_oid("1.2.804.2.1.1.1.1.3.1.1.2.0".parse::<Asn1Oid>().unwrap()),
        ] {
            round_trip(&curve);
        }
    }

    #[test]
    fn keys_on_two_curves_a_changed_ciphertext_and_params_of_another_type_are_refused() {
        let algo = DefaultAlgoBuilder::default().build();
        let (alice, _) = pairs(&EcKeyGenParams::new("P-256"));
        let (bob, _) = pairs(&EcKeyGenParams::new("P-384"));
        let (_, alice_private) = alice.into_parts();
        let (bob_public, _) = bob.into_parts();
        let error = algo
            .cipher()
            .encrypt_by_name("ECIES", &params(alice_private, bob_public), b"message")
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);

        let (alice, bob) = pairs(&EcKeyGenParams::new("P-256"));
        let (_, alice_private) = alice.into_parts();
        let (bob_public, _) = bob.into_parts();
        let params = params(alice_private, bob_public);
        let mut sealed = algo
            .cipher()
            .encrypt_by_name("ECIES", &params, b"message")
            .unwrap();
        sealed[0] ^= 1;
        let error = algo
            .cipher()
            .decrypt_by_name("ECIES", &params, &sealed)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidCiphertext);

        let error = algo
            .cipher()
            .encrypt_by_name("ECIES", &EcKeyGenParams::new("P-256"), b"message")
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}
