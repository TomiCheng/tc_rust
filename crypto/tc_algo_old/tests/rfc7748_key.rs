#![cfg(any(feature = "x25519", feature = "x448"))]

use tc_algo_old::{AnyKeyParams, AnyParams, AnyPrivateKey, AnyPublicKey};

fn assert_traits<T: Clone + Send + Sync + 'static>() {}

#[cfg(feature = "x25519")]
mod x25519 {
    use tc_cfrg_curves::{X25519PrivateKey, X25519PublicKey};

    use super::*;

    // The params are plain data, so any 32 bytes go in; the algorithm clamps and checks them
    fn private_key() -> X25519PrivateKey {
        X25519PrivateKey::new([7; 32])
    }

    #[test]
    fn an_x25519_key_goes_into_the_params_as_a_private_or_a_public_key() {
        let private_key = private_key();
        let public_key = private_key.generate_public_key();
        let private = AnyParams::new(AnyKeyParams::Private(AnyPrivateKey::X25519(private_key)));
        let public = AnyParams::new(AnyKeyParams::Public(AnyPublicKey::X25519(public_key)));
        assert!(matches!(
            private.key,
            AnyKeyParams::Private(AnyPrivateKey::X25519(_))
        ));
        assert!(matches!(
            public.key,
            AnyKeyParams::Public(AnyPublicKey::X25519(_))
        ));
    }

    #[test]
    fn debug_shows_the_algorithm_but_no_x25519_key_bytes() {
        let private = AnyPrivateKey::X25519(private_key());
        let public = AnyPublicKey::X25519(X25519PublicKey::new([9; 32]));
        assert_eq!(format!("{private:?}"), "X25519(..)");
        assert_eq!(format!("{public:?}"), "X25519(..)");
    }

    #[test]
    fn x25519_keys_can_be_cloned_and_sent_between_threads() {
        assert_traits::<X25519PrivateKey>();
        assert_traits::<X25519PublicKey>();
    }
}

#[cfg(feature = "x448")]
mod x448 {
    use tc_cfrg_curves::{X448PrivateKey, X448PublicKey};

    use super::*;

    // The params are plain data, so any 56 bytes go in; the algorithm clamps and checks them
    fn private_key() -> X448PrivateKey {
        X448PrivateKey::new([7; 56])
    }

    #[test]
    fn an_x448_key_goes_into_the_params_as_a_private_or_a_public_key() {
        let private_key = private_key();
        let public_key = private_key.generate_public_key();
        let private = AnyParams::new(AnyKeyParams::Private(AnyPrivateKey::X448(private_key)));
        let public = AnyParams::new(AnyKeyParams::Public(AnyPublicKey::X448(public_key)));
        assert!(matches!(
            private.key,
            AnyKeyParams::Private(AnyPrivateKey::X448(_))
        ));
        assert!(matches!(
            public.key,
            AnyKeyParams::Public(AnyPublicKey::X448(_))
        ));
    }

    #[test]
    fn debug_shows_the_algorithm_but_no_x448_key_bytes() {
        let private = AnyPrivateKey::X448(private_key());
        let public = AnyPublicKey::X448(X448PublicKey::new([9; 56]));
        assert_eq!(format!("{private:?}"), "X448(..)");
        assert_eq!(format!("{public:?}"), "X448(..)");
    }

    #[test]
    fn x448_keys_can_be_cloned_and_sent_between_threads() {
        assert_traits::<X448PrivateKey>();
        assert_traits::<X448PublicKey>();
    }
}
