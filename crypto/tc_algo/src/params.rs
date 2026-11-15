#[cfg(feature = "ascon-cxof128")]
mod ascon_cxof_params;
#[cfg(feature = "blake2xs")]
mod blake2xs_params;
#[cfg(feature = "blake3")]
mod blake3_params;
#[cfg(any(feature = "cshake128", feature = "cshake256"))]
mod cshake_params;
#[cfg(feature = "drbg-hmac-sha256")]
mod drbg_params;
#[cfg(feature = "ies")]
mod ies_dh_params;
mod key_length;
#[cfg(any(feature = "parallelhash128", feature = "parallelhash256"))]
mod parallel_hash_params;
#[cfg(feature = "rsa")]
mod rsa_key_gen_params;
#[cfg(feature = "sm2")]
pub(crate) mod sm2_keys;
#[cfg(any(feature = "tuplehash128", feature = "tuplehash256"))]
mod tuple_hash_params;

#[cfg(any(
    feature = "aes",
    feature = "des",
    feature = "desede",
    feature = "camellia",
    feature = "aria",
    feature = "sm4",
    feature = "seed",
    feature = "dstu7624-128",
    feature = "dstu7624-256",
    feature = "dstu7624-512",
    feature = "blowfish",
    feature = "twofish",
    feature = "serpent",
    feature = "tnepres",
    feature = "cast5",
    feature = "cast6",
    feature = "idea",
    feature = "noekeon",
    feature = "rijndael",
    feature = "skipjack",
    feature = "tea",
    feature = "xtea",
    feature = "rc2",
    feature = "rc5",
    feature = "rc5-64",
    feature = "rc6",
    feature = "gost28147",
    feature = "threefish-256",
    feature = "threefish-512",
    feature = "threefish-1024",
    feature = "chacha",
    feature = "xchacha20",
    feature = "rc4",
    feature = "vmpc",
    feature = "vmpc-ksa3",
    feature = "isaac",
    feature = "salsa20",
    feature = "xsalsa20",
    feature = "hc128",
    feature = "hc256",
    feature = "chacha20-poly1305",
    feature = "xchacha20-poly1305",
    feature = "ascon-aead128",
    feature = "ascon128",
    feature = "ascon128a",
    feature = "ascon80pq",
    feature = "grain128-aead",
    feature = "schwaemm128-128",
    feature = "schwaemm256-128",
    feature = "schwaemm192-192",
    feature = "schwaemm256-256",
    feature = "hmac-sha256",
    feature = "rsa",
    feature = "elgamal",
    feature = "naccache-stern",
    feature = "sm2",
    feature = "dh",
    feature = "hkdf",
    feature = "ml-kem"
))]
use core::any::Any;

#[cfg(feature = "ascon-cxof128")]
pub use ascon_cxof_params::AsconCXofParams;
#[cfg(feature = "blake2xs")]
pub use blake2xs_params::Blake2xsParams;
#[cfg(feature = "blake3")]
pub use blake3_params::Blake3Params;
#[cfg(any(feature = "cshake128", feature = "cshake256"))]
pub use cshake_params::CShakeParams;
#[cfg(feature = "drbg-hmac-sha256")]
pub use drbg_params::DrbgParams;
#[cfg(feature = "ies")]
pub use ies_dh_params::IesDhParams;
pub use key_length::KeyLength;
#[cfg(any(feature = "parallelhash128", feature = "parallelhash256"))]
pub use parallel_hash_params::ParallelHashParams;
#[cfg(feature = "rsa")]
pub use rsa_key_gen_params::RsaKeyGenParams;
#[cfg(any(
    feature = "aes",
    feature = "des",
    feature = "desede",
    feature = "camellia",
    feature = "aria",
    feature = "sm4",
    feature = "seed",
    feature = "dstu7624-128",
    feature = "dstu7624-256",
    feature = "dstu7624-512",
    feature = "blowfish",
    feature = "twofish",
    feature = "serpent",
    feature = "tnepres",
    feature = "cast5",
    feature = "cast6",
    feature = "idea",
    feature = "noekeon",
    feature = "rijndael",
    feature = "skipjack",
    feature = "tea",
    feature = "xtea",
    feature = "rc2",
    feature = "rc5",
    feature = "rc5-64",
    feature = "rc6",
    feature = "gost28147",
    feature = "threefish-256",
    feature = "threefish-512",
    feature = "threefish-1024",
    feature = "chacha20-poly1305",
    feature = "xchacha20-poly1305",
    feature = "ascon-aead128",
    feature = "ascon128",
    feature = "ascon128a",
    feature = "ascon80pq",
    feature = "grain128-aead",
    feature = "schwaemm128-128",
    feature = "schwaemm256-128",
    feature = "schwaemm192-192",
    feature = "schwaemm256-256",
))]
pub use tc_aead_cipher::AeadParamsOwned;
#[cfg(any(
    feature = "rc2",
    feature = "rc5",
    feature = "rc5-64",
    feature = "gost28147",
    feature = "threefish-256",
    feature = "threefish-512",
    feature = "threefish-1024"
))]
pub use tc_aead_cipher::ParamsWithAeadOwned;
#[cfg(any(
    feature = "aes",
    feature = "des",
    feature = "desede",
    feature = "camellia",
    feature = "aria",
    feature = "sm4",
    feature = "seed",
    feature = "dstu7624-128",
    feature = "dstu7624-256",
    feature = "dstu7624-512",
    feature = "blowfish",
    feature = "twofish",
    feature = "serpent",
    feature = "tnepres",
    feature = "cast5",
    feature = "cast6",
    feature = "idea",
    feature = "noekeon",
    feature = "rijndael",
    feature = "skipjack",
    feature = "tea",
    feature = "xtea",
    feature = "rc2",
    feature = "rc5",
    feature = "rc5-64",
    feature = "rc6",
    feature = "gost28147",
    feature = "threefish-256",
    feature = "threefish-512",
    feature = "threefish-1024",
    feature = "chacha",
    feature = "xchacha20",
    feature = "rc4",
    feature = "vmpc",
    feature = "vmpc-ksa3",
    feature = "isaac",
    feature = "salsa20",
    feature = "xsalsa20",
    feature = "hc128",
    feature = "hc256",
    feature = "chacha20-poly1305",
    feature = "xchacha20-poly1305",
    feature = "ascon-aead128",
    feature = "ascon128",
    feature = "ascon128a",
    feature = "ascon80pq",
    feature = "grain128-aead",
    feature = "schwaemm128-128",
    feature = "schwaemm256-128",
    feature = "schwaemm192-192",
    feature = "schwaemm256-256",
    feature = "hmac-sha256"
))]
pub use tc_block_cipher::{KeyOwned, KeyParams};
#[cfg(any(
    feature = "rc2",
    feature = "rc5",
    feature = "rc5-64",
    feature = "gost28147",
    feature = "threefish-256",
    feature = "threefish-512",
    feature = "threefish-1024"
))]
pub use tc_block_modes::ParamsWithIvOwned;
#[cfg(any(
    feature = "aes",
    feature = "des",
    feature = "desede",
    feature = "camellia",
    feature = "aria",
    feature = "sm4",
    feature = "seed",
    feature = "dstu7624-128",
    feature = "dstu7624-256",
    feature = "dstu7624-512",
    feature = "blowfish",
    feature = "twofish",
    feature = "serpent",
    feature = "tnepres",
    feature = "cast5",
    feature = "cast6",
    feature = "idea",
    feature = "noekeon",
    feature = "rijndael",
    feature = "skipjack",
    feature = "tea",
    feature = "xtea",
    feature = "rc2",
    feature = "rc5",
    feature = "rc5-64",
    feature = "rc6",
    feature = "gost28147",
    feature = "threefish-256",
    feature = "threefish-512",
    feature = "threefish-1024",
    feature = "chacha",
    feature = "xchacha20",
    feature = "rc4",
    feature = "vmpc",
    feature = "vmpc-ksa3",
    feature = "isaac",
    feature = "salsa20",
    feature = "xsalsa20",
    feature = "hc128",
    feature = "hc256",
    feature = "chacha20-poly1305",
    feature = "xchacha20-poly1305",
    feature = "ascon-aead128",
    feature = "ascon128",
    feature = "ascon128a",
    feature = "ascon80pq",
    feature = "grain128-aead",
    feature = "schwaemm128-128",
    feature = "schwaemm256-128",
    feature = "schwaemm192-192",
    feature = "schwaemm256-256"
))]
pub use tc_block_modes::{IvParams, KeyWithIvOwned};
#[cfg(feature = "dh")]
pub use tc_dh_key::standard_groups as dh_groups;
#[cfg(feature = "dh")]
pub use tc_dh_key::{DhParameters, DhPrivateKey, DhPublicKey};
#[cfg(feature = "gost28147")]
pub use tc_gost28147::{Gost28147ParamsOwned, s_box as gost28147_s_box};
#[cfg(feature = "hkdf")]
pub use tc_kdf::hkdf::HkdfParamsOwned;
#[cfg(feature = "ml-kem")]
pub use tc_ml_kem::{MlKemParameters, MlKemPrivateKey, MlKemPublicKey};
#[cfg(feature = "rc2")]
pub use tc_rc_cipher::Rc2ParamsOwned;
#[cfg(any(feature = "rc5", feature = "rc5-64"))]
pub use tc_rc_cipher::Rc5ParamsOwned;
#[cfg(feature = "rsa")]
pub use tc_rsa::{RsaKey, RsaKeyParams};
#[cfg(any(
    feature = "threefish-256",
    feature = "threefish-512",
    feature = "threefish-1024"
))]
pub use tc_threefish::ThreefishParamsOwned;
#[cfg(any(feature = "tuplehash128", feature = "tuplehash256"))]
pub use tuple_hash_params::TupleHashParams;

#[cfg(any(
    feature = "aes",
    feature = "des",
    feature = "desede",
    feature = "camellia",
    feature = "aria",
    feature = "sm4",
    feature = "seed",
    feature = "dstu7624-128",
    feature = "dstu7624-256",
    feature = "dstu7624-512",
    feature = "blowfish",
    feature = "twofish",
    feature = "serpent",
    feature = "tnepres",
    feature = "cast5",
    feature = "cast6",
    feature = "idea",
    feature = "noekeon",
    feature = "rijndael",
    feature = "skipjack",
    feature = "tea",
    feature = "xtea",
    feature = "rc2",
    feature = "rc5",
    feature = "rc5-64",
    feature = "rc6",
    feature = "gost28147",
    feature = "threefish-256",
    feature = "threefish-512",
    feature = "threefish-1024",
    feature = "chacha",
    feature = "xchacha20",
    feature = "rc4",
    feature = "vmpc",
    feature = "vmpc-ksa3",
    feature = "isaac",
    feature = "salsa20",
    feature = "xsalsa20",
    feature = "hc128",
    feature = "hc256",
    feature = "chacha20-poly1305",
    feature = "xchacha20-poly1305",
    feature = "ascon-aead128",
    feature = "ascon128",
    feature = "ascon128a",
    feature = "ascon80pq",
    feature = "grain128-aead",
    feature = "schwaemm128-128",
    feature = "schwaemm256-128",
    feature = "schwaemm192-192",
    feature = "schwaemm256-256",
    feature = "hmac-sha256",
    feature = "rsa",
    feature = "elgamal",
    feature = "naccache-stern",
    feature = "sm2",
    feature = "dh",
    feature = "hkdf",
    feature = "ml-kem"
))]
use crate::Params;

#[cfg(any(
    feature = "aes",
    feature = "des",
    feature = "desede",
    feature = "camellia",
    feature = "aria",
    feature = "sm4",
    feature = "seed",
    feature = "dstu7624-128",
    feature = "dstu7624-256",
    feature = "dstu7624-512",
    feature = "blowfish",
    feature = "twofish",
    feature = "serpent",
    feature = "tnepres",
    feature = "cast5",
    feature = "cast6",
    feature = "idea",
    feature = "noekeon",
    feature = "rijndael",
    feature = "skipjack",
    feature = "tea",
    feature = "xtea",
    feature = "rc2",
    feature = "rc5",
    feature = "rc5-64",
    feature = "rc6",
    feature = "gost28147",
    feature = "threefish-256",
    feature = "threefish-512",
    feature = "threefish-1024",
    feature = "chacha",
    feature = "xchacha20",
    feature = "rc4",
    feature = "vmpc",
    feature = "vmpc-ksa3",
    feature = "isaac",
    feature = "salsa20",
    feature = "xsalsa20",
    feature = "hc128",
    feature = "hc256",
    feature = "chacha20-poly1305",
    feature = "xchacha20-poly1305",
    feature = "ascon-aead128",
    feature = "ascon128",
    feature = "ascon128a",
    feature = "ascon80pq",
    feature = "grain128-aead",
    feature = "schwaemm128-128",
    feature = "schwaemm256-128",
    feature = "schwaemm192-192",
    feature = "schwaemm256-256",
    feature = "hmac-sha256"
))]
impl Params for KeyOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(any(
    feature = "aes",
    feature = "des",
    feature = "desede",
    feature = "camellia",
    feature = "aria",
    feature = "sm4",
    feature = "seed",
    feature = "dstu7624-128",
    feature = "dstu7624-256",
    feature = "dstu7624-512",
    feature = "blowfish",
    feature = "twofish",
    feature = "serpent",
    feature = "tnepres",
    feature = "cast5",
    feature = "cast6",
    feature = "idea",
    feature = "noekeon",
    feature = "rijndael",
    feature = "skipjack",
    feature = "tea",
    feature = "xtea",
    feature = "rc2",
    feature = "rc5",
    feature = "rc5-64",
    feature = "rc6",
    feature = "gost28147",
    feature = "threefish-256",
    feature = "threefish-512",
    feature = "threefish-1024",
    feature = "chacha",
    feature = "xchacha20",
    feature = "rc4",
    feature = "vmpc",
    feature = "vmpc-ksa3",
    feature = "isaac",
    feature = "salsa20",
    feature = "xsalsa20",
    feature = "hc128",
    feature = "hc256",
    feature = "chacha20-poly1305",
    feature = "xchacha20-poly1305",
    feature = "ascon-aead128",
    feature = "ascon128",
    feature = "ascon128a",
    feature = "ascon80pq",
    feature = "grain128-aead",
    feature = "schwaemm128-128",
    feature = "schwaemm256-128",
    feature = "schwaemm192-192",
    feature = "schwaemm256-256"
))]
impl Params for KeyWithIvOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// An engine's own params with an IV, as Bouncy Castle's ParametersWithIV. Each TParams is a type
// of its own, which a row downcasts to
#[cfg(any(
    feature = "rc2",
    feature = "rc5",
    feature = "rc5-64",
    feature = "gost28147",
    feature = "threefish-256",
    feature = "threefish-512",
    feature = "threefish-1024"
))]
impl<TParams: Send + Sync + 'static> Params for ParamsWithIvOwned<TParams> {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// An engine's own params with the nonce, tag size and initial AAD of an AEAD mode, which gives the
// engine the own params alone
#[cfg(any(
    feature = "rc2",
    feature = "rc5",
    feature = "rc5-64",
    feature = "gost28147",
    feature = "threefish-256",
    feature = "threefish-512",
    feature = "threefish-1024"
))]
impl<TParams: Send + Sync + 'static> Params for ParamsWithAeadOwned<TParams> {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "rc2")]
impl Params for Rc2ParamsOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(any(feature = "rc5", feature = "rc5-64"))]
impl Params for Rc5ParamsOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "gost28147")]
impl Params for Gost28147ParamsOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(any(
    feature = "threefish-256",
    feature = "threefish-512",
    feature = "threefish-1024"
))]
impl Params for ThreefishParamsOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(any(
    feature = "aes",
    feature = "des",
    feature = "desede",
    feature = "camellia",
    feature = "aria",
    feature = "sm4",
    feature = "seed",
    feature = "dstu7624-128",
    feature = "dstu7624-256",
    feature = "dstu7624-512",
    feature = "blowfish",
    feature = "twofish",
    feature = "serpent",
    feature = "tnepres",
    feature = "cast5",
    feature = "cast6",
    feature = "idea",
    feature = "noekeon",
    feature = "rijndael",
    feature = "skipjack",
    feature = "tea",
    feature = "xtea",
    feature = "rc2",
    feature = "rc5",
    feature = "rc5-64",
    feature = "rc6",
    feature = "gost28147",
    feature = "threefish-256",
    feature = "threefish-512",
    feature = "threefish-1024",
    feature = "chacha20-poly1305",
    feature = "xchacha20-poly1305",
    feature = "ascon-aead128",
    feature = "ascon128",
    feature = "ascon128a",
    feature = "ascon80pq",
    feature = "grain128-aead",
    feature = "schwaemm128-128",
    feature = "schwaemm256-128",
    feature = "schwaemm192-192",
    feature = "schwaemm256-256",
))]
impl Params for AeadParamsOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "hkdf")]
impl Params for HkdfParamsOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "ml-kem")]
impl Params for MlKemParameters {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "ml-kem")]
impl Params for MlKemPublicKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "ml-kem")]
impl Params for MlKemPrivateKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "rsa")]
impl Params for RsaKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// The keys of ElGamal encryption, which tc_elgamal has; whether tc_algo re-exports them is yet to be
// decided, as for the other key types of DH
#[cfg(feature = "elgamal")]
impl Params for tc_elgamal::ElGamalPublicKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "elgamal")]
impl Params for tc_elgamal::ElGamalPrivateKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "elgamal")]
impl Params for tc_elgamal::ElGamalParameters {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// The keys of Naccache-Stern and the params of its key pair generator, which tc_naccache_stern has
#[cfg(feature = "naccache-stern")]
impl Params for tc_naccache_stern::NaccacheSternPublicKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "naccache-stern")]
impl Params for tc_naccache_stern::NaccacheSternPrivateKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "naccache-stern")]
impl Params for tc_naccache_stern::NaccacheSternKeyGenerationParams {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// The EC keys of SM2 on sm2p256v1, as its key pair generator gives them
#[cfg(feature = "sm2")]
impl Params for sm2_keys::Sm2PublicKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "sm2")]
impl Params for sm2_keys::Sm2PrivateKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "dh")]
impl Params for DhParameters {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "dh")]
impl Params for DhPrivateKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "dh")]
impl Params for DhPublicKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}
