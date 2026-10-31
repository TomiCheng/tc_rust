//! `DhAgreement`：雙方得到同一個 MTI/A0 秘密；參數不同、弱訊息、順序錯誤時拒絕。

use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_bigint::{ArrayEncoding, BigUint, PaddedBigUint};
use tc_dh::{DhAgreement, DhAgreementError};
use tc_dh_key::standard_groups::{rfc2409_1024, rfc3526_2048};
use tc_dh_key::{
    DhError, DhKeyGenerationParams, DhKeyPairGenerator, DhParameters, DhPrivateKey, DhPublicKey,
};
use tc_modular::{ModMul, ModPow, NonZero};

type Agreement = DhAgreement<rand::rngs::ThreadRng>;

fn big(value: &PaddedBigUint) -> BigUint {
    BigUint::from(value.clone())
}

fn key_pairs(params: DhParameters) -> [(DhPublicKey, DhPrivateKey); 2] {
    let mut rng = rand::rng();
    let mut generator = DhKeyPairGenerator::new();
    generator
        .init(DhKeyGenerationParams::new(params, &mut rng))
        .unwrap();
    [
        generator.generate_key_pair().unwrap(),
        generator.generate_key_pair().unwrap(),
    ]
}

fn started(private_key: &DhPrivateKey) -> (Agreement, PaddedBigUint) {
    let mut agreement = DhAgreement::new(rand::rng());
    agreement.init(private_key).unwrap();
    let message = agreement.calculate_message().unwrap();
    (agreement, message)
}

fn finish(
    agreement: &Agreement,
    public_key: &DhPublicKey,
    message: &PaddedBigUint,
) -> Result<Vec<u8>, DhAgreementError> {
    let mut secret = vec![0; agreement.agreement_size()];
    agreement.calculate_agreement(public_key, message, &mut secret)?;
    Ok(secret)
}

#[test]
fn both_parties_reach_the_mti_a0_secret_as_p_sized_bytes() {
    let [(alice_public, alice_private), (bob_public, bob_private)] = key_pairs(rfc3526_2048());
    let (alice, alice_message) = started(&alice_private);
    let (bob, bob_message) = started(&bob_private);
    let secret = finish(&alice, &bob_public, &bob_message).unwrap();
    assert_eq!(secret, finish(&bob, &alice_public, &alice_message).unwrap());
    assert_eq!(secret.len(), 256);

    // y_B^r_A = (g^r_A)^x_B，所以秘密也等於 m_A^x_B · m_B^x_A。
    let p = NonZero::new(big(alice_private.params().p())).unwrap();
    let expected = big(&alice_message)
        .mod_pow(&big(bob_private.x()), &p)
        .mod_mul(&big(&bob_message).mod_pow(&big(alice_private.x()), &p), &p);
    let mut expected_bytes = vec![0; 256];
    let bytes = ArrayEncoding::<u8>::to_be(&expected);
    expected_bytes[256 - bytes.len()..].copy_from_slice(&bytes);
    assert_eq!(secret, expected_bytes);
}

#[test]
fn each_message_is_fresh() {
    let [(_, private_key), _] = key_pairs(rfc2409_1024());
    let mut agreement = DhAgreement::new(rand::rng());
    agreement.init(&private_key).unwrap();
    assert_ne!(
        agreement.calculate_message().unwrap(),
        agreement.calculate_message().unwrap()
    );
}

#[test]
fn steps_out_of_order_are_rejected() {
    let [(public_key, private_key), _] = key_pairs(rfc2409_1024());
    let mut agreement: Agreement = DhAgreement::new(rand::rng());
    assert_eq!(
        agreement.calculate_message(),
        Err(DhAgreementError::NotInitialized)
    );
    assert_eq!(
        agreement.calculate_agreement(&public_key, public_key.y(), &mut [0; 128]),
        Err(DhAgreementError::NotInitialized)
    );
    agreement.init(&private_key).unwrap();
    let message = public_key.y().clone();
    assert_eq!(
        finish(&agreement, &public_key, &message),
        Err(DhAgreementError::MessageNotCalculated)
    );

    // 重新 init 會丟掉上一次的一次性私鑰。
    agreement.calculate_message().unwrap();
    agreement.init(&private_key).unwrap();
    assert_eq!(
        finish(&agreement, &public_key, &message),
        Err(DhAgreementError::MessageNotCalculated)
    );
}

#[test]
fn a_public_key_on_other_parameters_is_rejected() {
    let [(_, private_key), _] = key_pairs(rfc3526_2048());
    let [(other_public, _), _] = key_pairs(rfc2409_1024());
    let (agreement, message) = started(&private_key);
    assert_eq!(
        finish(&agreement, &other_public, &message),
        Err(DhAgreementError::WrongParameters)
    );
}

#[test]
fn weak_messages_and_public_keys_are_rejected() {
    let params = rfc3526_2048();
    let [(public_key, private_key), _] = key_pairs(params.clone());
    let (agreement, message) = started(&private_key);
    let p = big(params.p());
    for (y, error) in [
        (BigUint::from(1u8), DhError::InvalidPublicValue),
        (&p - 1u32, DhError::InvalidPublicValue),
        (&p - 2u32, DhError::PublicValueOutsideSubgroup),
    ] {
        let weak = PaddedBigUint::from(y);
        assert_eq!(
            finish(&agreement, &public_key, &weak),
            Err(DhAgreementError::InvalidMessage(error))
        );
        let weak_key = DhPublicKey::new(weak, params.clone());
        assert_eq!(
            finish(&agreement, &weak_key, &message),
            Err(DhAgreementError::InvalidPublicKey(error))
        );
    }
}

#[test]
fn a_short_output_is_rejected() {
    let [(public_key, private_key), _] = key_pairs(rfc2409_1024());
    let (agreement, message) = started(&private_key);
    assert_eq!(
        agreement.calculate_agreement(&public_key, &message, &mut [0; 127]),
        Err(DhAgreementError::BufferTooSmall)
    );
}
