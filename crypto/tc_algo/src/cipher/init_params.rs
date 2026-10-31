use tc_zeroize::Zeroizing;

// What the cipher layers underneath receive at init, built from AnyParams only after the entry
// has checked them: one variant per kind of cipher, each the type its layers take
pub(super) enum InitParams {
    Symmetric(SymmetricParams),
    // A copy of the key, which the engine reads at init
    #[cfg(feature = "rsa")]
    Rsa(tc_rsa::RsaKey),
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

// The key and operation fields of a block cipher. Each trait returns a value that is really
// there: a field the mode does not use is never asked for, so the expects below cannot fire
// unless the table and the modes disagree. The key is a copy, wiped on drop
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
