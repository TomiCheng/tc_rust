//! The RSA key over the one integer type the crate shows outside.

use tc_asym_cipher::AsymmetricKeyParams;
use tc_bigint::PaddedBigUint;

use crate::{RsaKeyOwned, RsaKeyParams, RsaPrivateCrtKeyOwned};

/// An RSA key over [`PaddedBigUint`], the one integer type an RSA key
/// takes outside the crate, as Bouncy Castle's keys take `BigInteger`: the
/// engine that runs it turns it into the integers it computes on when it
/// is initialized, whichever they are. The variant tells how the key is
/// raised: [`Core`](Self::Core) with its one exponent, as Bouncy Castle's
/// `RsaKeyParameters`, and [`Crt`](Self::Crt) through the Chinese
/// Remainder Theorem, as its `RsaPrivateCrtKeyParameters`.
///
/// A [`PaddedBigUint`] keeps the width it is given, leading zero limbs
/// and all, so that its storage never shows how large a private value is,
/// as a trimmed integer's would. It is a container only: each variant
/// holds a key that checks itself once, when an operation calls
/// [`validate`](RsaKeyParams::validate), and wipes itself on drop. There
/// is no `Debug`, which would show the private values.
#[derive(Clone)]
pub enum RsaKey {
    /// A key of a modulus and one exponent: `e` for a public key, `d` for
    /// a private one without its CRT values.
    Core(RsaKeyOwned<PaddedBigUint>),
    /// A private key with its CRT values.
    Crt(RsaPrivateCrtKeyOwned<PaddedBigUint>),
}

/// The key raised by its one exponent. Constant time.
impl From<RsaKeyOwned<PaddedBigUint>> for RsaKey {
    fn from(key: RsaKeyOwned<PaddedBigUint>) -> Self {
        Self::Core(key)
    }
}

/// The key raised through the CRT. Constant time.
impl From<RsaPrivateCrtKeyOwned<PaddedBigUint>> for RsaKey {
    fn from(key: RsaPrivateCrtKeyOwned<PaddedBigUint>) -> Self {
        Self::Crt(key)
    }
}

/// The public key of `rsa`, its values copied at the width `rsa` holds
/// them, and marked as passed, as `rsa` checks a key when it builds it.
/// Constant time.
#[cfg(feature = "rustcrypto")]
impl From<crate::RsaKeyRustCrypto> for RsaKey {
    fn from(key: crate::RsaKeyRustCrypto) -> Self {
        let (n, e) = (padded(key.modulus()), padded(key.exponent()));
        Self::Core(RsaKeyOwned::new(false, n, e).into_validated())
    }
}

/// The private key of `rsa` with its CRT values, each copied at the width
/// `rsa` holds it, and marked as passed, as `rsa` checks a key when it
/// builds it. Constant time.
#[cfg(feature = "rustcrypto")]
impl From<crate::RsaPrivateCrtKeyRustCrypto> for RsaKey {
    fn from(key: crate::RsaPrivateCrtKeyRustCrypto) -> Self {
        use crate::RsaPrivateCrtKeyParams;

        Self::Crt(
            RsaPrivateCrtKeyOwned::new(
                padded(key.modulus()),
                padded(key.public_exponent()),
                padded(key.exponent()),
                padded(key.p()),
                padded(key.q()),
                padded(key.dp()),
                padded(key.dq()),
                padded(key.q_inv()),
            )
            .into_validated(),
        )
    }
}

/// `value` at the whole of the width `rsa` holds it at, through its
/// big-endian bytes, which are wiped afterwards. Constant time: the bytes
/// follow the width, not the value.
#[cfg(feature = "rustcrypto")]
fn padded(value: &rsa::BoxedUint) -> PaddedBigUint {
    use tc_bigint::ArrayEncoding;
    use tc_zeroize::Zeroize;

    let mut bytes = value.to_be_bytes();
    let Ok(padded) = PaddedBigUint::from_be(&bytes);
    bytes.zeroize();
    padded
}

/// Whether the key is private: as the [`Core`](RsaKey::Core) key says,
/// and always for a [`Crt`](RsaKey::Crt) one. Constant time.
impl AsymmetricKeyParams for RsaKey {
    fn is_private_key(&self) -> bool {
        match self {
            Self::Core(key) => key.is_private_key(),
            Self::Crt(key) => key.is_private_key(),
        }
    }
}

/// The modulus, the exponent the key is raised by, `d` for a
/// [`Crt`](RsaKey::Crt) key, and the check of the key the variant holds,
/// once. Constant time, but for `validate`, which is variable time: only
/// for public values, as the modulus is.
impl RsaKeyParams<PaddedBigUint> for RsaKey {
    fn modulus(&self) -> &PaddedBigUint {
        match self {
            Self::Core(key) => key.modulus(),
            Self::Crt(key) => key.modulus(),
        }
    }

    fn exponent(&self) -> &PaddedBigUint {
        match self {
            Self::Core(key) => key.exponent(),
            Self::Crt(key) => key.exponent(),
        }
    }

    fn validate(&self) -> bool {
        match self {
            Self::Core(key) => key.validate(),
            Self::Crt(key) => key.validate(),
        }
    }
}

#[cfg(test)]
mod tests {
    use tc_asym_cipher::AsymmetricKeyParams;
    use tc_bigint::PaddedBigUint;

    use super::RsaKey;
    use crate::{RsaKeyOwned, RsaKeyParams, RsaPrivateCrtKeyOwned};

    fn int(value: u32) -> PaddedBigUint {
        PaddedBigUint::from(value)
    }

    /// The textbook key, p = 61 and q = 53, marked as checked, as its
    /// modulus has small factors.
    fn core(private: bool) -> RsaKey {
        let exponent = if private { 2753 } else { 17 };
        RsaKey::from(RsaKeyOwned::new(private, int(3233), int(exponent)).into_validated())
    }

    fn crt() -> RsaKey {
        RsaKey::from(
            RsaPrivateCrtKeyOwned::new(
                int(3233),
                int(17),
                int(2753),
                int(61),
                int(53),
                int(53),
                int(49),
                int(38),
            )
            .into_validated(),
        )
    }

    #[test]
    fn a_core_key_is_private_as_it_says_and_a_crt_key_always_is() {
        assert!(!core(false).is_private_key());
        assert!(core(true).is_private_key());
        assert!(crt().is_private_key());
    }

    #[test]
    fn each_variant_gives_its_modulus_and_the_exponent_it_is_raised_by() {
        for (key, exponent) in [(core(false), 17), (core(true), 2753), (crt(), 2753)] {
            assert_eq!(key.modulus(), &int(3233));
            assert_eq!(key.exponent(), &int(exponent));
        }
    }

    #[test]
    fn each_variant_is_checked_as_the_key_it_holds() {
        assert!(core(false).validate());
        assert!(crt().validate());
        let unchecked = RsaKey::from(RsaKeyOwned::new(false, int(3233), int(17)));
        assert!(!unchecked.validate());
        let passing = RsaKey::from(RsaKeyOwned::new(false, int(1009 * 1013), int(17)));
        assert!(passing.clone().validate());
    }

    #[cfg(feature = "rustcrypto")]
    #[test]
    fn a_key_of_rsa_comes_over_value_for_value() {
        use rand::SeedableRng;
        use rand::rngs::StdRng;
        use rsa::traits::{PrivateKeyParts, PublicKeyParts};
        use tc_bigint::ArrayEncoding;

        use crate::{RsaKeyRustCrypto, RsaPrivateCrtKeyRustCrypto};

        let theirs = rsa::RsaPrivateKey::new(&mut StdRng::seed_from_u64(1), 1024).unwrap();
        let bytes = |value: &PaddedBigUint| -> alloc::vec::Vec<u8> { value.to_be() };
        let private = RsaKey::from(RsaPrivateCrtKeyRustCrypto::new(theirs.clone()).unwrap());
        let public = RsaKey::from(RsaKeyRustCrypto::new(theirs.to_public_key()));
        assert!(private.is_private_key() && !public.is_private_key());
        assert!(private.validate() && public.validate());
        assert_eq!(
            bytes(private.modulus()),
            theirs.n().as_ref().to_be_bytes().to_vec()
        );
        assert_eq!(bytes(private.exponent()), theirs.d().to_be_bytes().to_vec());
        assert_eq!(bytes(public.exponent()), theirs.e().to_be_bytes().to_vec());
    }
}
