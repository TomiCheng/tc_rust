//! `DhBasicAgreement`：雙方得到同一個秘密 y^x mod p，固定長度；參數不同、弱公鑰、
//! 結果為 1 時拒絕。

use tc_agreement::{Agreement, AgreementInit};
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_bigint::{ArrayEncoding, BigUint, PaddedBigUint};
use tc_dh::{DhAgreementError, DhBasicAgreement};
use tc_dh_key::standard_groups::{rfc2409_1024, rfc3526_2048};
use tc_dh_key::{
    DhError, DhKeyGenerationParams, DhKeyPairGenerator, DhParameters, DhPrivateKey, DhPublicKey,
};
use tc_modular::{ModPow, NonZero};

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

fn agree(
    private_key: &DhPrivateKey,
    public_key: &DhPublicKey,
) -> Result<Vec<u8>, DhAgreementError> {
    let mut agreement = DhBasicAgreement::new();
    agreement.init(private_key)?;
    let mut secret = vec![0; agreement.agreement_size()];
    agreement.calculate_agreement(public_key, &mut secret)?;
    Ok(secret)
}

#[test]
fn both_parties_reach_y_to_the_x_as_p_sized_bytes() {
    let [(alice_public, alice_private), (bob_public, bob_private)] = key_pairs(rfc3526_2048());
    let secret = agree(&alice_private, &bob_public).unwrap();
    assert_eq!(secret, agree(&bob_private, &alice_public).unwrap());
    assert_eq!(secret.len(), 256);

    let p = NonZero::new(big(alice_private.params().p())).unwrap();
    let expected = big(bob_public.y()).mod_pow(&big(alice_private.x()), &p);
    let mut expected_bytes = vec![0; 256];
    let bytes = ArrayEncoding::<u8>::to_be(&expected);
    expected_bytes[256 - bytes.len()..].copy_from_slice(&bytes);
    assert_eq!(secret, expected_bytes);
}

#[test]
fn a_public_key_on_other_parameters_is_rejected() {
    let [(_, private_key), _] = key_pairs(rfc3526_2048());
    let [(other_public, _), _] = key_pairs(rfc2409_1024());
    assert_eq!(
        agree(&private_key, &other_public),
        Err(DhAgreementError::WrongParameters)
    );
}

#[test]
fn weak_public_keys_are_rejected() {
    let params = rfc3526_2048();
    let [(_, private_key), _] = key_pairs(params.clone());
    let p = big(params.p());
    for (y, error) in [
        (BigUint::from(1u8), DhError::InvalidPublicValue),
        (&p - 1u32, DhError::InvalidPublicValue),
        // p ≡ 7 (mod 8)：−2 不是二次剩餘，不在 q 階子群裡。
        (&p - 2u32, DhError::PublicValueOutsideSubgroup),
    ] {
        let public_key = DhPublicKey::new(PaddedBigUint::from(y), params.clone());
        assert_eq!(
            agree(&private_key, &public_key),
            Err(DhAgreementError::InvalidPublicKey(error))
        );
    }
}

#[test]
fn a_shared_secret_of_one_is_rejected() {
    // 沒有 q 的參數：2 在模 23 下的階是 11，所以 2^11 = 1。
    let params = DhParameters::new(PaddedBigUint::from(23u8), PaddedBigUint::from(5u8)).with_m(0);
    let private_key = DhPrivateKey::new(PaddedBigUint::from(11u8), params.clone());
    let public_key = DhPublicKey::new(PaddedBigUint::from(2u8), params);
    assert_eq!(
        agree(&private_key, &public_key),
        Err(DhAgreementError::InvalidAgreement)
    );
}

#[test]
fn misuse_is_reported() {
    let [(public_key, private_key), _] = key_pairs(rfc3526_2048());
    assert_eq!(
        DhBasicAgreement::new().calculate_agreement(&public_key, &mut [0; 256]),
        Err(DhAgreementError::NotInitialized)
    );
    let mut agreement = DhBasicAgreement::new();
    agreement.init(&private_key).unwrap();
    assert_eq!(
        agreement.calculate_agreement(&public_key, &mut [0; 255]),
        Err(DhAgreementError::BufferTooSmall)
    );
    let invalid = DhPrivateKey::new(
        PaddedBigUint::from(3u8),
        DhParameters::new(PaddedBigUint::from(24u8), PaddedBigUint::from(2u8)),
    );
    assert_eq!(
        DhBasicAgreement::new().init(&invalid),
        Err(DhAgreementError::InvalidParameters(DhError::InvalidModulus))
    );
}
