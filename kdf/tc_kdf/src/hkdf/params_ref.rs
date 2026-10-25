use crate::hkdf::HkdfParams;

/// Borrowed [`HkdfParams`]. The caller owns the bytes and wipes them; nothing is checked here.
#[derive(Clone, Copy)]
pub struct HkdfParamsRef<'a> {
    ikm: &'a [u8],
    salt: &'a [u8],
    info: &'a [u8],
    skip_extract: bool,
}

impl<'a> HkdfParamsRef<'a> {
    /// Extract and expand, as BC's `HkdfParameters(ikm, salt, info)`; an empty `salt` stands for
    /// none. Constant time.
    pub const fn new(ikm: &'a [u8], salt: &'a [u8], info: &'a [u8]) -> Self {
        Self {
            ikm,
            salt,
            info,
            skip_extract: false,
        }
    }

    /// Expand only, with `prk` as the pseudorandom key, as BC's `SkipExtractParameters`.
    /// Constant time.
    pub const fn expand_only(prk: &'a [u8], info: &'a [u8]) -> Self {
        Self {
            ikm: prk,
            salt: &[],
            info,
            skip_extract: true,
        }
    }
}

impl HkdfParams for HkdfParamsRef<'_> {
    /// Constant time: returns the slice without reading it.
    fn ikm(&self) -> &[u8] {
        self.ikm
    }

    /// Constant time: returns the slice without reading it.
    fn salt(&self) -> &[u8] {
        self.salt
    }

    /// Constant time: returns the slice without reading it.
    fn info(&self) -> &[u8] {
        self.info
    }

    /// Constant time.
    fn skip_extract(&self) -> bool {
        self.skip_extract
    }
}
