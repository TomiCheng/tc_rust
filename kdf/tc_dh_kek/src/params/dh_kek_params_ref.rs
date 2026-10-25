use tc_asn1::Asn1Oid;

use crate::DhKekParams;

/// Borrowed [`DhKekParams`]. The caller owns the bytes and wipes them; nothing is checked here,
/// [`DhKek`](crate::DhKek) accepts any parameters in `init`, as BC does.
#[derive(Clone, Copy)]
pub struct DhKekParamsRef<'a> {
    algorithm: &'a Asn1Oid,
    key_size: u32,
    z: &'a [u8],
    extra_info: &'a [u8],
}

impl<'a> DhKekParamsRef<'a> {
    /// A KEK of `key_size` bits for `algorithm` from ZZ, without `partyAInfo`. Constant time.
    pub const fn new(algorithm: &'a Asn1Oid, key_size: u32, z: &'a [u8]) -> Self {
        Self {
            algorithm,
            key_size,
            z,
            extra_info: &[],
        }
    }

    /// As [`new`](Self::new), with party A's user keying material in `partyAInfo`. Constant
    /// time.
    pub const fn with_extra_info(
        algorithm: &'a Asn1Oid,
        key_size: u32,
        z: &'a [u8],
        extra_info: &'a [u8],
    ) -> Self {
        Self {
            algorithm,
            key_size,
            z,
            extra_info,
        }
    }
}

impl DhKekParams for DhKekParamsRef<'_> {
    /// Constant time: returns the reference without reading it.
    fn algorithm(&self) -> &Asn1Oid {
        self.algorithm
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
