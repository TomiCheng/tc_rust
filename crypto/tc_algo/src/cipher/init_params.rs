use tc_zeroize::Zeroizing;

// What the cipher layers underneath receive at init, built from AnyParams only after the entry
// has checked the fields its mode needs. Each trait returns a value that is really there: a
// field the mode does not use is never asked for, so the expects below cannot fire unless the
// table and the modes disagree. The key is a copy, wiped on drop
pub(super) struct InitParams {
    pub(super) key: Zeroizing<Vec<u8>>,
    pub(super) iv: Option<Vec<u8>>,
    pub(super) tag_len: Option<usize>,
    pub(super) aad: Vec<u8>,
}

impl tc_block_cipher::KeyParams for InitParams {
    fn key(&self) -> &[u8] {
        &self.key
    }
}

impl tc_block_modes::IvParams for InitParams {
    fn iv(&self) -> &[u8] {
        self.iv
            .as_deref()
            .expect("the entry requires an IV for every mode that reads one")
    }
}

impl tc_aead_cipher::NonceParams for InitParams {
    fn nonce(&self) -> &[u8] {
        self.iv
            .as_deref()
            .expect("the entry requires a nonce for every AEAD mode")
    }
}

impl tc_aead_cipher::MacSizeParams for InitParams {
    fn mac_size(&self) -> usize {
        self.tag_len
            .expect("the entry requires a tag length for every AEAD mode")
    }
}

// No associated data is an empty one
impl tc_aead_cipher::InitialAadParams for InitParams {
    fn initial_aad(&self) -> &[u8] {
        &self.aad
    }
}
