// The MACs that name their algorithm rather than take one. Those of Bouncy Castle's MacUtilities
// have its names and aliases; the rest are not in its table, so their names follow the classes'
// AlgorithmName, in upper case, with the size added where one class gives several rows
#[allow(
    unused_imports,
    reason = "unused when every OID row of this file is off"
)]
use tc_asn1::NamedOid;

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

#[cfg(feature = "kmac")]
const KMAC128_OIDS: &[NamedOid] = &[
    NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x15],
        "2.16.840.1.101.3.4.2.21",
        "id-Kmac128",
    ),
    NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x13],
        "2.16.840.1.101.3.4.2.19",
        "id-KmacWithSHAKE128",
    ),
];

#[cfg(feature = "kmac")]
const KMAC256_OIDS: &[NamedOid] = &[
    NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x16],
        "2.16.840.1.101.3.4.2.22",
        "id-Kmac256",
    ),
    NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x14],
        "2.16.840.1.101.3.4.2.20",
        "id-KmacWithSHAKE256",
    ),
];

#[cfg(feature = "dstu7564-mac")]
const DSTU7564_MAC_256_OIDS: &[NamedOid] = &[NamedOid::new(
    &[
        0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x04,
    ],
    "1.2.804.2.1.1.1.1.2.2.4",
    "dstu7564mac_256",
)];

#[cfg(feature = "dstu7564-mac")]
const DSTU7564_MAC_384_OIDS: &[NamedOid] = &[NamedOid::new(
    &[
        0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x05,
    ],
    "1.2.804.2.1.1.1.1.2.2.5",
    "dstu7564mac_384",
)];

#[cfg(feature = "dstu7564-mac")]
const DSTU7564_MAC_512_OIDS: &[NamedOid] = &[NamedOid::new(
    &[
        0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x06,
    ],
    "1.2.804.2.1.1.1.1.2.2.6",
    "dstu7564mac_512",
)];

#[cfg(feature = "dstu7624-mac")]
const DSTU7624_MAC_128_OIDS: &[NamedOid] = &[NamedOid::new(
    &[
        0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x03, 0x04, 0x01,
    ],
    "1.2.804.2.1.1.1.1.3.4.1",
    "dstu7624cmac_128",
)];

#[cfg(feature = "dstu7624-mac")]
const DSTU7624_MAC_256_OIDS: &[NamedOid] = &[NamedOid::new(
    &[
        0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x03, 0x04, 0x02,
    ],
    "1.2.804.2.1.1.1.1.3.4.2",
    "dstu7624cmac_256",
)];

#[cfg(feature = "dstu7624-mac")]
const DSTU7624_MAC_512_OIDS: &[NamedOid] = &[NamedOid::new(
    &[
        0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x03, 0x04, 0x03,
    ],
    "1.2.804.2.1.1.1.1.3.4.3",
    "dstu7624cmac_512",
)];

// The state and output bits for which Bouncy Castle's SkeinEngine has a precomputed state
#[cfg(feature = "skein-mac")]
const SKEIN_SIZES: [(usize, usize); 13] = [
    (256, 128),
    (256, 160),
    (256, 224),
    (256, 256),
    (512, 128),
    (512, 160),
    (512, 224),
    (512, 256),
    (512, 384),
    (512, 512),
    (1024, 384),
    (1024, 512),
    (1024, 1024),
];

// The tag of the DSTU 7624 MAC is a whole block
#[cfg(feature = "dstu7624-mac")]
const WHOLE_BLOCK: &str = "a whole block is a valid DSTU 7624 tag";

pub(super) fn rows() -> Vec<MacEntry> {
    #[allow(unused_mut, reason = "nothing is added when skein-mac is off")]
    let mut rows = vec![
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
        #[cfg(feature = "poly1305")]
        MacEntry::new(names(&["POLY1305"]), &[], Need::Forbidden, || {
            Box::new(Mapped::key_only(tc_poly1305::Poly1305::new()))
        }),
        #[cfg(feature = "kmac")]
        MacEntry::new(names(&["KMAC128"]), KMAC128_OIDS, Need::Forbidden, || {
            Box::new(Mapped::key_only(tc_kmac::KMac::new(128, b"")))
        }),
        #[cfg(feature = "kmac")]
        MacEntry::new(names(&["KMAC256"]), KMAC256_OIDS, Need::Forbidden, || {
            Box::new(Mapped::key_only(tc_kmac::KMac::new(256, b"")))
        }),
        #[cfg(feature = "dstu7564-mac")]
        MacEntry::new(
            names(&["DSTU7564MAC-256"]),
            DSTU7564_MAC_256_OIDS,
            Need::Forbidden,
            || Box::new(Mapped::key_only(tc_dstu_macs::Dstu7564Mac::new(256))),
        ),
        #[cfg(feature = "dstu7564-mac")]
        MacEntry::new(
            names(&["DSTU7564MAC-384"]),
            DSTU7564_MAC_384_OIDS,
            Need::Forbidden,
            || Box::new(Mapped::key_only(tc_dstu_macs::Dstu7564Mac::new(384))),
        ),
        #[cfg(feature = "dstu7564-mac")]
        MacEntry::new(
            names(&["DSTU7564MAC-512"]),
            DSTU7564_MAC_512_OIDS,
            Need::Forbidden,
            || Box::new(Mapped::key_only(tc_dstu_macs::Dstu7564Mac::new(512))),
        ),
        #[cfg(feature = "dstu7624-mac")]
        MacEntry::new(
            names(&["DSTU7624MAC-128"]),
            DSTU7624_MAC_128_OIDS,
            Need::Forbidden,
            || {
                Box::new(Mapped::key_only(
                    tc_dstu_macs::Dstu7624Mac128::new(128).expect(WHOLE_BLOCK),
                ))
            },
        ),
        #[cfg(feature = "dstu7624-mac")]
        MacEntry::new(
            names(&["DSTU7624MAC-256"]),
            DSTU7624_MAC_256_OIDS,
            Need::Forbidden,
            || {
                Box::new(Mapped::key_only(
                    tc_dstu_macs::Dstu7624Mac256::new(256).expect(WHOLE_BLOCK),
                ))
            },
        ),
        #[cfg(feature = "dstu7624-mac")]
        MacEntry::new(
            names(&["DSTU7624MAC-512"]),
            DSTU7624_MAC_512_OIDS,
            Need::Forbidden,
            || {
                Box::new(Mapped::key_only(
                    tc_dstu_macs::Dstu7624Mac512::new(512).expect(WHOLE_BLOCK),
                ))
            },
        ),
    ];
    #[cfg(feature = "skein-mac")]
    rows.extend(SKEIN_SIZES.map(|(state, output)| {
        MacEntry::new(
            vec![format!("SKEIN-MAC-{state}-{output}")],
            &[],
            Need::Forbidden,
            move || Box::new(Mapped::key_only(tc_skein_mac::SkeinMac::new(state, output))),
        )
    }));
    rows
}
