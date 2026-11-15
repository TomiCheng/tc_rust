use core::any::Any;
use core::error::Error;

use tc_agreement::{Agreement, AgreementInit};
use tc_asn1::Asn1Oid;
use tc_bigint::PaddedBigUint;
use tc_ec_core::Curve;
use tc_ec_key::EcPrivateKey;
use tc_ecdh_v2::EcdhBasicAgreement;
use tc_f2m_curve::F2mCtCurve;
use tc_fp_curve::FpCtCurve;
use tc_fp_custom::{
    SM2P256V1FieldElement, SecP128R1FieldElement, SecP160R1FieldElement, SecP160R2FieldElement,
    SecP192K1FieldElement, SecP192R1FieldElement, SecP224K1FieldElement, SecP224R1FieldElement,
    SecP256K1FieldElement, SecP256R1FieldElement, SecP384R1FieldElement, SecP521R1FieldElement,
    SecPCtCurve,
};
use tc_ies::{IesEngine, IesError, IesParamsRef};
use tc_kdf::kdf::Kdf2;
use tc_macs::Hmac;
use tc_sha::Sha1Digest;

use super::ies::{Ies, IesInit};
use crate::cipher::{Cipher, CipherDirection, CipherEntry};
use crate::params::IesEcParams;
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

type Try = fn(CipherDirection, &dyn Any) -> Option<Result<Box<dyn Process>, AlgoError>>;

// The curve types the row takes: the generic ones of tc_fp_curve and tc_f2m_curve, which hold any
// prime or binary curve, and the special ones of tc_fp_custom
const CURVES: &[Try] = &[
    engine::<&'static FpCtCurve<'static>>,
    engine::<&'static F2mCtCurve>,
    engine::<&'static SecPCtCurve<SecP128R1FieldElement>>,
    engine::<&'static SecPCtCurve<SecP160R1FieldElement>>,
    engine::<&'static SecPCtCurve<SecP160R2FieldElement>>,
    engine::<&'static SecPCtCurve<SecP192K1FieldElement>>,
    engine::<&'static SecPCtCurve<SecP192R1FieldElement>>,
    engine::<&'static SecPCtCurve<SecP224K1FieldElement>>,
    engine::<&'static SecPCtCurve<SecP224R1FieldElement>>,
    engine::<&'static SecPCtCurve<SecP256K1FieldElement>>,
    engine::<&'static SecPCtCurve<SecP256R1FieldElement>>,
    engine::<&'static SecPCtCurve<SecP384R1FieldElement>>,
    engine::<&'static SecPCtCurve<SecP521R1FieldElement>>,
    engine::<&'static SecPCtCurve<SM2P256V1FieldElement>>,
];

// The engine over the curve C, initialized, when params are an IesEcParams<C>; None when they are
// not
fn engine<C>(
    direction: CipherDirection,
    params: &dyn Any,
) -> Option<Result<Box<dyn Process>, AlgoError>>
where
    C: Curve<Scalar = PaddedBigUint> + 'static,
    EcdhBasicAgreement<C>:
        Agreement<PublicKey = tc_ec_key::EcPublicKey<C>> + AgreementInit<EcPrivateKey<C>>,
    <EcdhBasicAgreement<C> as Agreement>::Error: Error + Send + Sync + 'static,
    <EcdhBasicAgreement<C> as AgreementInit<EcPrivateKey<C>>>::Error: Error + Send + Sync + 'static,
{
    let params = params.downcast_ref::<IesEcParams<C>>()?;
    let mut engine = IesEngine::new(
        EcdhBasicAgreement::<C>::new(),
        Kdf2::new(Sha1Digest::new()),
        Hmac::new(Sha1Digest::new()),
    );
    let result = engine.init(
        direction.into(),
        params.private_key(),
        params.public_key(),
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
        let params = params.as_any();
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

    use rand::rngs::SysRng;
    use rand_core::UnwrapErr;
    use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
    use tc_bigint::{ArrayEncoding, PaddedBigUint};
    use tc_ec_core::Curve;
    use tc_ec_key::{EcKeyGenerationParams, EcKeyPairGenerator, EcPrivateKey, EcPublicKey};
    use tc_f2m_curve::F2mCtCurve;
    use tc_f2m_curve::named_curves::SECT233K1;
    use tc_fp_curve::named_curves::BRAINPOOLP256R1;
    use tc_fp_curve::{FpCtCurve, FpField};
    use tc_fp_custom::named_curves::SECP192R1;
    use tc_fp_custom::{SecP192R1FieldElement, SecPCtCurve};

    use crate::params::IesEcParams;
    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind, Params};

    static SECP192R1_CURVE: LazyLock<SecPCtCurve<SecP192R1FieldElement>> =
        LazyLock::new(|| SECP192R1.ct_curve());
    static BRAINPOOL_FIELD: LazyLock<FpField> = LazyLock::new(|| BRAINPOOLP256R1.field());
    static BRAINPOOL_CURVE: LazyLock<FpCtCurve<'static>> =
        LazyLock::new(|| BRAINPOOLP256R1.ct_curve(&BRAINPOOL_FIELD));
    static SECT233K1_CURVE: LazyLock<F2mCtCurve> = LazyLock::new(|| SECT233K1.ct_curve());

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn pair<C>(g: C::Point) -> (EcPublicKey<C>, EcPrivateKey<C>)
    where
        C: Curve<Scalar = PaddedBigUint>,
    {
        let mut generator = EcKeyPairGenerator::<C, _>::new(UnwrapErr(SysRng));
        generator.init(&EcKeyGenerationParams::new(g)).unwrap();
        generator.generate_key_pair().unwrap()
    }

    fn params<C: Curve<Scalar = PaddedBigUint>>(
        private_key: &EcPrivateKey<C>,
        public_key: &EcPublicKey<C>,
    ) -> IesEcParams<C> {
        IesEcParams::new(
            private_key.clone(),
            public_key.clone(),
            vec![1, 2, 3, 4, 5, 6, 7, 8],
            vec![8, 7, 6, 5, 4, 3, 2, 1],
            64,
        )
    }

    // Each side puts its own private key with the other's public key; both reach the same Z
    fn round_trip(alice: &dyn Params, bob: &dyn Params) {
        let algo = DefaultAlgoBuilder::default().build();
        let message = b"a message of no particular length";
        let sealed = algo
            .cipher()
            .encrypt_by_name("ECIES", alice, message)
            .unwrap();
        assert_eq!(sealed.len(), message.len() + 20);
        let opened = algo
            .cipher()
            .decrypt_by_name("ecies", bob, &sealed)
            .unwrap();
        assert_eq!(opened, message);
    }

    // The vector of Bouncy Castle's ECIESTest on secp192r1, as tc_ies tests it, through the row
    #[test]
    fn the_row_gives_bouncy_castles_vector_on_secp192r1() {
        let curve: &'static SecPCtCurve<SecP192R1FieldElement> = &SECP192R1_CURVE;
        let g = SECP192R1.ct_generator(curve);
        let d = <PaddedBigUint as ArrayEncoding<u8>>::from_be(&hex(
            "1a8d598fc15bf0fd89030b5cb1111aeb92ae8baf5ea475fb",
        ))
        .unwrap();
        let q = curve
            .decode_point(&hex("0262b12d60690cdcf330babab6e69763b471f994dd702d16a5"))
            .unwrap();
        let private_key =
            EcPrivateKey::<&'static SecPCtCurve<SecP192R1FieldElement>>::new(g.clone(), d).unwrap();
        let public_key =
            EcPublicKey::<&'static SecPCtCurve<SecP192R1FieldElement>>::new(g, &q).unwrap();
        let params = params(&private_key, &public_key);

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

    // One row takes a generic prime curve, brainpoolP256r1, and a binary one, sect233k1
    #[test]
    fn the_row_takes_keys_on_a_generic_prime_curve_and_on_a_binary_curve() {
        let curve: &'static FpCtCurve<'static> = &BRAINPOOL_CURVE;
        let (alice_public, alice_private) =
            pair::<&'static FpCtCurve<'static>>(BRAINPOOLP256R1.ct_generator(curve));
        let (bob_public, bob_private) =
            pair::<&'static FpCtCurve<'static>>(BRAINPOOLP256R1.ct_generator(curve));
        round_trip(
            &params(&alice_private, &bob_public),
            &params(&bob_private, &alice_public),
        );

        let curve: &'static F2mCtCurve = &SECT233K1_CURVE;
        let (alice_public, alice_private) =
            pair::<&'static F2mCtCurve>(SECT233K1.ct_generator(curve));
        let (bob_public, bob_private) = pair::<&'static F2mCtCurve>(SECT233K1.ct_generator(curve));
        round_trip(
            &params(&alice_private, &bob_public),
            &params(&bob_private, &alice_public),
        );
    }

    #[test]
    fn a_changed_ciphertext_and_params_of_another_type_are_refused() {
        let curve: &'static FpCtCurve<'static> = &BRAINPOOL_CURVE;
        let (public_key, private_key) =
            pair::<&'static FpCtCurve<'static>>(BRAINPOOLP256R1.ct_generator(curve));
        let params = params(&private_key, &public_key);
        let algo = DefaultAlgoBuilder::default().build();
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
            .encrypt_by_name("ECIES", &public_key_only(), b"message")
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }

    // Params that are no IesEcParams
    fn public_key_only() -> impl Params {
        crate::params::KeyOwned::new(vec![0; 16])
    }
}
