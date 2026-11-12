// The keys added after RSA, EC and RFC 7748: each goes into the params like those, so these check
// what can differ per algorithm, the Debug output and the thread-safety of the wrapped key types

#[allow(
    unused_imports,
    reason = "unused when every one of these key features is off"
)]
use tc_algo_old::{AnyKeyParams, AnyParams, AnyPrivateKey, AnyPublicKey};

fn assert_traits<T: Clone + Send + Sync + 'static>() {}

#[cfg(feature = "ed25519")]
#[test]
fn ed25519_keys_go_into_the_params_and_show_only_the_algorithm() {
    let private_key = tc_cfrg_curves::Ed25519PrivateKey::new([7; 32]);
    let public_key = private_key.generate_public_key();
    let private = AnyParams::new(AnyKeyParams::Private(AnyPrivateKey::Ed25519(private_key)));
    let public = AnyPublicKey::Ed25519(public_key);
    assert_eq!(
        format!("{private:?}"),
        "AnyParams { key: Private(Ed25519(..)), op: AnyOpParams { iv: None, tag_len: None, aad: None } }"
    );
    assert_eq!(format!("{public:?}"), "Ed25519(..)");
}

#[cfg(feature = "ed448")]
#[test]
fn ed448_keys_go_into_the_params_and_show_only_the_algorithm() {
    let private_key = tc_cfrg_curves::Ed448PrivateKey::new([7; 57]);
    let public_key = private_key.generate_public_key();
    let private = AnyPrivateKey::Ed448(private_key);
    let public = AnyPublicKey::Ed448(public_key);
    assert_eq!(format!("{private:?}"), "Ed448(..)");
    assert_eq!(format!("{public:?}"), "Ed448(..)");
}

#[cfg(feature = "ml-kem")]
#[test]
fn ml_kem_keys_go_into_the_params_and_show_only_the_algorithm() {
    use tc_ml_kem::{MlKemParameters, MlKemPrivateKey, MlKemPublicKey};

    let params = MlKemParameters::ML_KEM_768;
    let private = AnyPrivateKey::MlKem(MlKemPrivateKey::from_seed(params, [7; 64]));
    // The params are plain data, so even an encoding of the wrong length goes in
    let public = AnyPublicKey::MlKem(MlKemPublicKey::from_encoding(params, vec![0; 4]));
    assert_eq!(format!("{private:?}"), "MlKem(..)");
    assert_eq!(format!("{public:?}"), "MlKem(..)");
}

#[test]
fn every_wrapped_key_type_can_be_cloned_and_sent_between_threads() {
    #[cfg(feature = "ed25519")]
    {
        assert_traits::<tc_cfrg_curves::Ed25519PrivateKey>();
        assert_traits::<tc_cfrg_curves::Ed25519PublicKey>();
    }
    #[cfg(feature = "ed448")]
    {
        assert_traits::<tc_cfrg_curves::Ed448PrivateKey>();
        assert_traits::<tc_cfrg_curves::Ed448PublicKey>();
    }
    #[cfg(feature = "dh")]
    {
        assert_traits::<tc_dh_key::DhPrivateKey>();
        assert_traits::<tc_dh_key::DhPublicKey>();
    }
    #[cfg(feature = "dsa")]
    {
        assert_traits::<tc_dsa_key::DsaPrivateKey>();
        assert_traits::<tc_dsa_key::DsaPublicKey>();
    }
    #[cfg(feature = "elgamal")]
    {
        assert_traits::<tc_elgamal::ElGamalPrivateKey>();
        assert_traits::<tc_elgamal::ElGamalPublicKey>();
    }
    #[cfg(feature = "gost3410")]
    {
        assert_traits::<tc_gost3410_key::Gost3410PrivateKey>();
        assert_traits::<tc_gost3410_key::Gost3410PublicKey>();
    }
    #[cfg(feature = "ml-kem")]
    {
        assert_traits::<tc_ml_kem::MlKemPrivateKey>();
        assert_traits::<tc_ml_kem::MlKemPublicKey>();
    }
    #[cfg(feature = "naccache-stern")]
    {
        assert_traits::<tc_naccache_stern::NaccacheSternPrivateKey>();
        assert_traits::<tc_naccache_stern::NaccacheSternPublicKey>();
    }
    assert_traits::<AnyPrivateKey>();
    assert_traits::<AnyPublicKey>();
}
