use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::EcdhKekParams;

/// Borrowed [`EcdhKekParams`]. The caller owns the bytes and wipes them; nothing
/// is checked here, and the functions accept any parameters in `init`, as BC
/// does.
#[derive(Clone, Copy)]
pub struct EcdhKekParamsRef<'a> {
    key_info: &'a AlgorithmIdentifier,
    key_size: u32,
    z: &'a [u8],
    extra_info: &'a [u8],
}

impl<'a> EcdhKekParamsRef<'a> {
    /// A KEK of `key_size` bits for `key_info` from Z, without user keying
    /// material. Constant time.
    pub const fn new(key_info: &'a AlgorithmIdentifier, key_size: u32, z: &'a [u8]) -> Self {
        Self {
            key_info,
            key_size,
            z,
            extra_info: &[],
        }
    }

    /// As [`new`](Self::new), with the sender's user keying material. Constant
    /// time.
    pub const fn with_extra_info(
        key_info: &'a AlgorithmIdentifier,
        key_size: u32,
        z: &'a [u8],
        extra_info: &'a [u8],
    ) -> Self {
        Self {
            key_info,
            key_size,
            z,
            extra_info,
        }
    }
}

impl EcdhKekParams for EcdhKekParamsRef<'_> {
    /// Constant time: returns the reference without reading it.
    fn key_info(&self) -> &AlgorithmIdentifier {
        self.key_info
    }

    /// Constant time.
    fn key_size(&self) -> u32 {
        self.key_size
    }

    /// Constant time: returns the slice without reading it.
    fn z(&self) -> &[u8] {
        self.z
    }

    /// Constant time: returns the slice without reading it.
    fn extra_info(&self) -> &[u8] {
        self.extra_info
    }
}
