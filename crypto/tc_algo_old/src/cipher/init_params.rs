use tc_zeroize::Zeroizing;

// What the cipher layers underneath receive at init, built from AnyParams only after the entry
// has checked them: one variant per kind of cipher, each the type its layers take
pub(super) enum InitParams {
    Symmetric(SymmetricParams),
    // A copy of the key, which the engine reads at init
    #[cfg(feature = "rsa")]
    Rsa(tc_rsa::RsaKey),
    #[cfg(feature = "elgamal")]
    ElGamal(ElGamalKey),
    #[cfg(feature = "naccache-stern")]
    NaccacheStern(NaccacheSternKey),
    #[cfg(feature = "sm2")]
    Sm2(Sm2Key),
}

// The part of InitParams one kind of cipher takes; None for another kind's, which the entry never
// builds for it
pub(super) trait InitPart {
    fn part(params: &InitParams) -> Option<&Self>;
}

impl InitPart for SymmetricParams {
    #[allow(
        irrefutable_let_patterns,
        reason = "Symmetric is the only variant when every asymmetric feature is off"
    )]
    fn part(params: &InitParams) -> Option<&Self> {
        if let InitParams::Symmetric(params) = params {
            Some(params)
        } else {
            None
        }
    }
}

#[cfg(feature = "rsa")]
impl InitPart for tc_rsa::RsaKey {
    fn part(params: &InitParams) -> Option<&Self> {
        if let InitParams::Rsa(key) = params {
            Some(key)
        } else {
            None
        }
    }
}

// ElGamal takes a public key to encrypt and a private key to decrypt, each a type of its own;
// this puts the two behind one type, which the paddings wrapping the engine can pass on
#[cfg(feature = "elgamal")]
pub(super) enum ElGamalKey {
    Public(tc_elgamal::ElGamalPublicKey),
    Private(tc_elgamal::ElGamalPrivateKey),
}

#[cfg(feature = "elgamal")]
impl tc_asym_cipher::AsymmetricKeyParams for ElGamalKey {
    fn is_private_key(&self) -> bool {
        matches!(self, Self::Private(_))
    }
}

#[cfg(feature = "elgamal")]
impl InitPart for ElGamalKey {
    fn part(params: &InitParams) -> Option<&Self> {
        if let InitParams::ElGamal(key) = params {
            Some(key)
        } else {
            None
        }
    }
}

// Naccache-Stern also has a type for each key: the public key encrypts, the private key encrypts
// or decrypts
#[cfg(feature = "naccache-stern")]
pub(super) enum NaccacheSternKey {
    Public(tc_naccache_stern::NaccacheSternPublicKey),
    Private(tc_naccache_stern::NaccacheSternPrivateKey),
}

#[cfg(feature = "naccache-stern")]
impl InitPart for NaccacheSternKey {
    fn part(params: &InitParams) -> Option<&Self> {
        if let InitParams::NaccacheStern(key) = params {
            Some(key)
        } else {
            None
        }
    }
}

// The curve SM2 runs on, the type of the Sm2p256v1 variant of the EC keys
#[cfg(feature = "sm2")]
pub(super) type Sm2p256v1 = &'static tc_fp_custom::SecPCtCurve<tc_fp_custom::SM2P256V1FieldElement>;

// Like ElGamal, SM2 encrypts with the public key and decrypts with the private key
#[cfg(feature = "sm2")]
pub(super) enum Sm2Key {
    Public(Box<tc_ec_key::EcPublicKey<Sm2p256v1>>),
    Private(Box<tc_ec_key::EcPrivateKey<Sm2p256v1>>),
}

#[cfg(feature = "sm2")]
impl InitPart for Sm2Key {
    fn part(params: &InitParams) -> Option<&Self> {
        if let InitParams::Sm2(key) = params {
            Some(key)
        } else {
            None
        }
    }
}

// The key and operation fields of a block or stream cipher. Each trait returns a value that is
// really there: a field the cipher does not use is never asked for, so the expects below cannot
// fire unless the table and the ciphers disagree. The key is a copy, wiped on drop
pub(super) struct SymmetricParams {
    pub(super) key: Zeroizing<Vec<u8>>,
    pub(super) iv: Option<Vec<u8>>,
    pub(super) tag_len: Option<usize>,
    pub(super) aad: Vec<u8>,
}

impl tc_block_cipher::KeyParams for SymmetricParams {
    fn key(&self) -> &[u8] {
        &self.key
    }
}

impl tc_block_modes::IvParams for SymmetricParams {
    fn iv(&self) -> &[u8] {
        self.iv
            .as_deref()
            .expect("the entry requires an IV for every mode that reads one")
    }
}

// The parameters some block ciphers take beyond the key, at the values Bouncy Castle gives a bare
// key
#[cfg(feature = "rc2")]
impl tc_rc_cipher::Rc2Params for SymmetricParams {
    fn effective_key_bits(&self) -> usize {
        self.key.len() * 8
    }
}

#[cfg(any(feature = "rc5", feature = "rc5-64"))]
impl tc_rc_cipher::Rc5Params for SymmetricParams {
    fn rounds(&self) -> usize {
        tc_rc_cipher::RC5_DEFAULT_ROUNDS
    }
}

// A zero tweak
#[cfg(feature = "threefish")]
impl tc_threefish::ThreefishParams for SymmetricParams {
    fn tweak(&self) -> Option<&[u8]> {
        None
    }
}

#[cfg(feature = "gost28147")]
impl tc_gost28147::Gost28147Params for SymmetricParams {
    fn s_box(&self) -> &[u8] {
        &tc_gost28147::s_box::DEFAULT
    }
}

impl tc_stream_cipher::KeyParams for SymmetricParams {
    fn key(&self) -> &[u8] {
        &self.key
    }
}

impl tc_stream_cipher::IvParams for SymmetricParams {
    fn iv(&self) -> &[u8] {
        self.iv
            .as_deref()
            .expect("the entry requires an IV for every stream cipher that reads one")
    }
}

impl tc_aead_cipher::NonceParams for SymmetricParams {
    fn nonce(&self) -> &[u8] {
        self.iv
            .as_deref()
            .expect("the entry requires a nonce for every AEAD mode")
    }
}

impl tc_aead_cipher::MacSizeParams for SymmetricParams {
    fn mac_size(&self) -> usize {
        self.tag_len
            .expect("the entry requires a tag length for every AEAD mode")
    }
}

// No associated data is an empty one
impl tc_aead_cipher::InitialAadParams for SymmetricParams {
    fn initial_aad(&self) -> &[u8] {
        &self.aad
    }
}
