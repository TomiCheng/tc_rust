use tc_block_cipher::KeyParams;
use tc_block_modes::IvParams;

// What the MACs underneath receive at init, built from AnyMacParams after the entry has checked it.
// One type implements every parameter trait they ask for, so the rows need no more than a MAC
#[derive(Clone, Copy)]
pub(super) struct MacParams<'a> {
    pub(super) key: &'a [u8],
    pub(super) iv: &'a [u8],
}

impl KeyParams for MacParams<'_> {
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl IvParams for MacParams<'_> {
    fn iv(&self) -> &[u8] {
        self.iv
    }
}

// The parameters some ciphers take beyond the key, at the values Bouncy Castle gives them for a
// bare key
#[cfg(feature = "rc2")]
impl tc_rc_cipher::Rc2Params for MacParams<'_> {
    fn effective_key_bits(&self) -> usize {
        self.key.len() * 8
    }
}

#[cfg(feature = "rc5")]
impl tc_rc_cipher::Rc5Params for MacParams<'_> {
    fn rounds(&self) -> usize {
        tc_rc_cipher::RC5_DEFAULT_ROUNDS
    }
}

// Skein takes the key through a trait of its own, in which the key may be absent
#[cfg(feature = "skein-mac")]
impl tc_skein_mac::SkeinParams for MacParams<'_> {
    fn key(&self) -> Option<&[u8]> {
        Some(self.key)
    }
}

// The S-box of Bouncy Castle's Gost28147Mac, which is not that of its cipher
#[cfg(feature = "gost28147-mac")]
impl tc_gost28147::Gost28147Params for MacParams<'_> {
    fn s_box(&self) -> &[u8] {
        &tc_gost28147::s_box::E_A
    }
}
