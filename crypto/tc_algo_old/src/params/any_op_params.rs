// The public fields of an operation, beside the key. Each algorithm takes the ones it needs and
// refuses in init the ones it has no use for; the fields of other algorithms come with them
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct AnyOpParams {
    // The IV, or the nonce of an AEAD mode
    pub iv: Option<Vec<u8>>,
    // The length of an AEAD tag, in bytes
    pub tag_len: Option<usize>,
    // Associated data an AEAD mode authenticates without encrypting, Bouncy Castle's
    // AeadParameters.AssociatedText
    pub aad: Option<Vec<u8>>,
}
