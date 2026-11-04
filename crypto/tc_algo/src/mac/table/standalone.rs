// The MACs that name their algorithm rather than take one: DES for ISO 9797, the rest of their own.
// The names and the aliases follow Bouncy Castle's MacUtilities
#[allow(unused_imports, reason = "unused when every MAC of this file is off")]
use super::names;
use crate::mac::MacEntry;
#[allow(unused_imports, reason = "unused when every MAC of this file is off")]
use crate::mac::dyn_mac::Mapped;
#[allow(unused_imports, reason = "unused when every MAC of this file is off")]
use crate::need::Need;

// Their IV is a DES or GOST block, of zeros when the caller gives none
#[cfg(any(feature = "iso9797-mac", feature = "gost28147-mac"))]
const BLOCK_BYTES: usize = 8;

pub(super) fn rows() -> Vec<MacEntry> {
    vec![
        #[cfg(feature = "iso9797-mac")]
        MacEntry::new(
            names(&[
                "ISO9797ALG3MAC",
                "ISO9797ALG3",
                "DESWITHISO9797",
                "DESISO9797MAC",
            ]),
            &[],
            Need::Optional,
            || {
                Box::new(Mapped::new(
                    tc_iso9797_mac::Iso9797Alg3Mac::new(),
                    BLOCK_BYTES,
                ))
            },
        ),
        #[cfg(feature = "iso9797-mac")]
        MacEntry::new(
            names(&[
                "ISO9797ALG3WITHISO7816-4PADDING",
                "ISO9797ALG3MACWITHISO7816-4PADDING",
            ]),
            &[],
            Need::Optional,
            || {
                Box::new(Mapped::new(
                    tc_iso9797_mac::Iso9797Alg3Mac::with_padding(
                        tc_block_padding::Iso7816d4Padding::new(),
                    ),
                    BLOCK_BYTES,
                ))
            },
        ),
        #[cfg(feature = "gost28147-mac")]
        MacEntry::new(
            names(&["GOST28147MAC", "GOST28147"]),
            &[],
            Need::Optional,
            || {
                Box::new(Mapped::new(
                    tc_gost28147_mac::Gost28147Mac::new(),
                    BLOCK_BYTES,
                ))
            },
        ),
        #[cfg(feature = "vmpc-mac")]
        MacEntry::new(
            names(&["VMPCMAC", "VMPC", "VMPC-MAC"]),
            &[],
            Need::Required,
            || Box::new(Mapped::key_only(tc_macs::VmpcMac::new())),
        ),
        #[cfg(feature = "siphash")]
        MacEntry::new(
            names(&["SIPHASH-2-4", "SIPHASH"]),
            &[],
            Need::Forbidden,
            || Box::new(Mapped::key_only(tc_macs::SipHash::new())),
        ),
    ]
}
