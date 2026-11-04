#[allow(
    unused_imports,
    reason = "the table is empty when every digest feature is off"
)]
use tc_asn1::NamedOid;

use super::DigestEntry;
#[cfg(feature = "ascon-hash-legacy")]
use super::dyn_digest::DynDigest;

// The two digests from before NIST standardized Ascon, deprecated in their crate; they are here for
// old data
#[cfg(feature = "ascon-hash-legacy")]
#[allow(deprecated, reason = "this row exists for old data")]
fn ascon_hash() -> Box<dyn DynDigest> {
    Box::new(tc_ascon_hash::AsconDigest::new(
        tc_ascon_hash::AsconParameters::AsconHash,
    ))
}

#[cfg(feature = "ascon-hash-legacy")]
#[allow(deprecated, reason = "this row exists for old data")]
fn ascon_hasha() -> Box<dyn DynDigest> {
    Box::new(tc_ascon_hash::AsconDigest::new(
        tc_ascon_hash::AsconParameters::AsconHashA,
    ))
}

// One row per digest. Names, aliases and OIDs follow Bouncy Castle's DigestUtilities: the first
// name is the canonical one, the first OID is the digest's own (DigestInfo uses it), and the rest
// map to the same row as in Bouncy Castle, HMAC OIDs included. The digests its table leaves out are
// here too, named as their classes name themselves but in upper case, as the rest of the table is
pub(super) const DIGESTS: &[DigestEntry] = &[
    #[cfg(feature = "md2")]
    DigestEntry::new(
        &["MD2"],
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x02],
            "1.2.840.113549.2.2",
            "md2",
        )],
        || Box::new(tc_md::Md2Digest::new()),
    ),
    #[cfg(feature = "md4")]
    DigestEntry::new(
        &["MD4"],
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x04],
            "1.2.840.113549.2.4",
            "md4",
        )],
        || Box::new(tc_md::Md4Digest::new()),
    ),
    #[cfg(feature = "md5")]
    DigestEntry::new(
        &["MD5"],
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05],
            "1.2.840.113549.2.5",
            "md5",
        )],
        || Box::new(tc_md::Md5Digest::new()),
    ),
    #[cfg(feature = "sha1")]
    DigestEntry::new(
        &["SHA-1", "SHA1"],
        &[
            NamedOid::new(&[0x2b, 0x0e, 0x03, 0x02, 0x1a], "1.3.14.3.2.26", "id-sha1"),
            NamedOid::new(
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x07],
                "1.2.840.113549.2.7",
                "id-hmacWithSHA1",
            ),
            NamedOid::new(
                &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x08, 0x01, 0x02],
                "1.3.6.1.5.5.8.1.2",
                "hmac-sha1",
            ),
        ],
        || Box::new(tc_sha::Sha1Digest::new()),
    ),
    #[cfg(feature = "sha224")]
    DigestEntry::new(
        &["SHA-224", "SHA224"],
        &[
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04],
                "2.16.840.1.101.3.4.2.4",
                "id-sha224",
            ),
            NamedOid::new(
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x08],
                "1.2.840.113549.2.8",
                "id-hmacWithSHA224",
            ),
        ],
        || Box::new(tc_sha::Sha224Digest::new()),
    ),
    #[cfg(feature = "sha256")]
    DigestEntry::new(
        &["SHA-256", "SHA256"],
        &[
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
                "2.16.840.1.101.3.4.2.1",
                "id-sha256",
            ),
            NamedOid::new(
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09],
                "1.2.840.113549.2.9",
                "id-hmacWithSHA256",
            ),
        ],
        || Box::new(tc_sha::Sha256Digest::new()),
    ),
    #[cfg(feature = "sha384")]
    DigestEntry::new(
        &["SHA-384", "SHA384"],
        &[
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02],
                "2.16.840.1.101.3.4.2.2",
                "id-sha384",
            ),
            NamedOid::new(
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0a],
                "1.2.840.113549.2.10",
                "id-hmacWithSHA384",
            ),
        ],
        || Box::new(tc_sha::Sha384Digest::new()),
    ),
    #[cfg(feature = "sha512")]
    DigestEntry::new(
        &["SHA-512", "SHA512"],
        &[
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03],
                "2.16.840.1.101.3.4.2.3",
                "id-sha512",
            ),
            NamedOid::new(
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0b],
                "1.2.840.113549.2.11",
                "id-hmacWithSHA512",
            ),
        ],
        || Box::new(tc_sha::Sha512Digest::new()),
    ),
    #[cfg(feature = "sha512-224")]
    DigestEntry::new(
        &[
            "SHA-512/224",
            "SHA512/224",
            "SHA512-224",
            "SHA512(224)",
            "SHA-512(224)",
        ],
        &[
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05],
                "2.16.840.1.101.3.4.2.5",
                "id-sha512-224",
            ),
            NamedOid::new(
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0c],
                "1.2.840.113549.2.12",
                "id-hmacWithSHA512-224",
            ),
        ],
        || Box::new(tc_sha::Sha512tDigest::new(224)),
    ),
    #[cfg(feature = "sha512-256")]
    DigestEntry::new(
        &[
            "SHA-512/256",
            "SHA512/256",
            "SHA512-256",
            "SHA512(256)",
            "SHA-512(256)",
        ],
        &[
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06],
                "2.16.840.1.101.3.4.2.6",
                "id-sha512-256",
            ),
            NamedOid::new(
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0d],
                "1.2.840.113549.2.13",
                "id-hmacWithSHA512-256",
            ),
        ],
        || Box::new(tc_sha::Sha512tDigest::new(256)),
    ),
    #[cfg(feature = "sha3-224")]
    DigestEntry::new(
        &["SHA3-224"],
        &[
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07],
                "2.16.840.1.101.3.4.2.7",
                "id-sha3-224",
            ),
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0d],
                "2.16.840.1.101.3.4.2.13",
                "id-hmacWithSHA3-224",
            ),
        ],
        || Box::new(tc_keccak::Sha3Digest::new(224)),
    ),
    #[cfg(feature = "sha3-256")]
    DigestEntry::new(
        &["SHA3-256"],
        &[
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08],
                "2.16.840.1.101.3.4.2.8",
                "id-sha3-256",
            ),
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0e],
                "2.16.840.1.101.3.4.2.14",
                "id-hmacWithSHA3-256",
            ),
        ],
        || Box::new(tc_keccak::Sha3Digest::new(256)),
    ),
    #[cfg(feature = "sha3-384")]
    DigestEntry::new(
        &["SHA3-384"],
        &[
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09],
                "2.16.840.1.101.3.4.2.9",
                "id-sha3-384",
            ),
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0f],
                "2.16.840.1.101.3.4.2.15",
                "id-hmacWithSHA3-384",
            ),
        ],
        || Box::new(tc_keccak::Sha3Digest::new(384)),
    ),
    #[cfg(feature = "sha3-512")]
    DigestEntry::new(
        &["SHA3-512"],
        &[
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a],
                "2.16.840.1.101.3.4.2.10",
                "id-sha3-512",
            ),
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x10],
                "2.16.840.1.101.3.4.2.16",
                "id-hmacWithSHA3-512",
            ),
        ],
        || Box::new(tc_keccak::Sha3Digest::new(512)),
    ),
    #[cfg(feature = "keccak-224")]
    DigestEntry::new(&["KECCAK-224", "KECCAK224"], &[], || {
        Box::new(tc_keccak::KeccakDigest::new(224))
    }),
    #[cfg(feature = "keccak-256")]
    DigestEntry::new(&["KECCAK-256", "KECCAK256"], &[], || {
        Box::new(tc_keccak::KeccakDigest::new(256))
    }),
    #[cfg(feature = "keccak-288")]
    DigestEntry::new(&["KECCAK-288", "KECCAK288"], &[], || {
        Box::new(tc_keccak::KeccakDigest::new(288))
    }),
    #[cfg(feature = "keccak-384")]
    DigestEntry::new(&["KECCAK-384", "KECCAK384"], &[], || {
        Box::new(tc_keccak::KeccakDigest::new(384))
    }),
    #[cfg(feature = "keccak-512")]
    DigestEntry::new(&["KECCAK-512", "KECCAK512"], &[], || {
        Box::new(tc_keccak::KeccakDigest::new(512))
    }),
    #[cfg(feature = "shake128")]
    DigestEntry::new(
        &["SHAKE128-256", "SHAKE128", "SHAKE-128"],
        &[NamedOid::new(
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0b],
            "2.16.840.1.101.3.4.2.11",
            "id-shake128",
        )],
        || Box::new(tc_keccak::ShakeDigest::new(128)),
    ),
    #[cfg(feature = "shake256")]
    DigestEntry::new(
        &["SHAKE256-512", "SHAKE256", "SHAKE-256"],
        &[NamedOid::new(
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0c],
            "2.16.840.1.101.3.4.2.12",
            "id-shake256",
        )],
        || Box::new(tc_keccak::ShakeDigest::new(256)),
    ),
    #[cfg(feature = "blake2b-160")]
    DigestEntry::new(
        &["BLAKE2B-160"],
        &[NamedOid::new(
            &[
                0x2b, 0x06, 0x01, 0x04, 0x01, 0x8d, 0x3a, 0x0c, 0x02, 0x01, 0x05,
            ],
            "1.3.6.1.4.1.1722.12.2.1.5",
            "id_blake2b160",
        )],
        || Box::new(tc_blake::Blake2bDigest::with_digest_size(160)),
    ),
    #[cfg(feature = "blake2b-256")]
    DigestEntry::new(
        &["BLAKE2B-256"],
        &[NamedOid::new(
            &[
                0x2b, 0x06, 0x01, 0x04, 0x01, 0x8d, 0x3a, 0x0c, 0x02, 0x01, 0x08,
            ],
            "1.3.6.1.4.1.1722.12.2.1.8",
            "id_blake2b256",
        )],
        || Box::new(tc_blake::Blake2bDigest::with_digest_size(256)),
    ),
    #[cfg(feature = "blake2b-384")]
    DigestEntry::new(
        &["BLAKE2B-384"],
        &[NamedOid::new(
            &[
                0x2b, 0x06, 0x01, 0x04, 0x01, 0x8d, 0x3a, 0x0c, 0x02, 0x01, 0x0c,
            ],
            "1.3.6.1.4.1.1722.12.2.1.12",
            "id_blake2b384",
        )],
        || Box::new(tc_blake::Blake2bDigest::with_digest_size(384)),
    ),
    #[cfg(feature = "blake2b-512")]
    DigestEntry::new(
        &["BLAKE2B-512"],
        &[NamedOid::new(
            &[
                0x2b, 0x06, 0x01, 0x04, 0x01, 0x8d, 0x3a, 0x0c, 0x02, 0x01, 0x10,
            ],
            "1.3.6.1.4.1.1722.12.2.1.16",
            "id_blake2b512",
        )],
        || Box::new(tc_blake::Blake2bDigest::with_digest_size(512)),
    ),
    #[cfg(feature = "blake2s-128")]
    DigestEntry::new(
        &["BLAKE2S-128"],
        &[NamedOid::new(
            &[
                0x2b, 0x06, 0x01, 0x04, 0x01, 0x8d, 0x3a, 0x0c, 0x02, 0x02, 0x04,
            ],
            "1.3.6.1.4.1.1722.12.2.2.4",
            "id_blake2s128",
        )],
        || Box::new(tc_blake::Blake2sDigest::with_digest_size(128)),
    ),
    #[cfg(feature = "blake2s-160")]
    DigestEntry::new(
        &["BLAKE2S-160"],
        &[NamedOid::new(
            &[
                0x2b, 0x06, 0x01, 0x04, 0x01, 0x8d, 0x3a, 0x0c, 0x02, 0x02, 0x05,
            ],
            "1.3.6.1.4.1.1722.12.2.2.5",
            "id_blake2s160",
        )],
        || Box::new(tc_blake::Blake2sDigest::with_digest_size(160)),
    ),
    #[cfg(feature = "blake2s-224")]
    DigestEntry::new(
        &["BLAKE2S-224"],
        &[NamedOid::new(
            &[
                0x2b, 0x06, 0x01, 0x04, 0x01, 0x8d, 0x3a, 0x0c, 0x02, 0x02, 0x07,
            ],
            "1.3.6.1.4.1.1722.12.2.2.7",
            "id_blake2s224",
        )],
        || Box::new(tc_blake::Blake2sDigest::with_digest_size(224)),
    ),
    #[cfg(feature = "blake2s-256")]
    DigestEntry::new(
        &["BLAKE2S-256"],
        &[NamedOid::new(
            &[
                0x2b, 0x06, 0x01, 0x04, 0x01, 0x8d, 0x3a, 0x0c, 0x02, 0x02, 0x08,
            ],
            "1.3.6.1.4.1.1722.12.2.2.8",
            "id_blake2s256",
        )],
        || Box::new(tc_blake::Blake2sDigest::with_digest_size(256)),
    ),
    #[cfg(feature = "blake3-256")]
    DigestEntry::new(
        &["BLAKE3-256"],
        &[NamedOid::new(
            &[
                0x2b, 0x06, 0x01, 0x04, 0x01, 0x8d, 0x3a, 0x0c, 0x02, 0x03, 0x08,
            ],
            "1.3.6.1.4.1.1722.12.2.3.8",
            "blake3_256",
        )],
        || Box::new(tc_blake::Blake3Digest::with_digest_size(256)),
    ),
    #[cfg(feature = "dstu7564-256")]
    DigestEntry::new(
        &["DSTU7564-256"],
        &[NamedOid::new(
            &[
                0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x01,
            ],
            "1.2.804.2.1.1.1.1.2.2.1",
            "dstu7564digest_256",
        )],
        || Box::new(tc_dstu7564::Dstu7564Digest::new(256)),
    ),
    #[cfg(feature = "dstu7564-384")]
    DigestEntry::new(
        &["DSTU7564-384"],
        &[NamedOid::new(
            &[
                0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02,
            ],
            "1.2.804.2.1.1.1.1.2.2.2",
            "dstu7564digest_384",
        )],
        || Box::new(tc_dstu7564::Dstu7564Digest::new(384)),
    ),
    #[cfg(feature = "dstu7564-512")]
    DigestEntry::new(
        &["DSTU7564-512"],
        &[NamedOid::new(
            &[
                0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x03,
            ],
            "1.2.804.2.1.1.1.1.2.2.3",
            "dstu7564digest_512",
        )],
        || Box::new(tc_dstu7564::Dstu7564Digest::new(512)),
    ),
    #[cfg(feature = "gost3411")]
    DigestEntry::new(
        &["GOST3411"],
        &[NamedOid::new(
            &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x09],
            "1.2.643.2.2.9",
            "id-GostR3411-94",
        )],
        || Box::new(tc_gost3411::Gost3411Digest::new()),
    ),
    #[cfg(feature = "gost3411-2012-256")]
    DigestEntry::new(
        &["GOST3411-2012-256"],
        &[NamedOid::new(
            &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02],
            "1.2.643.7.1.1.2.2",
            "id-tc26-gost3411-12-256",
        )],
        || Box::new(tc_gost3411::Gost3411_2012_256Digest::new()),
    ),
    #[cfg(feature = "gost3411-2012-512")]
    DigestEntry::new(
        &["GOST3411-2012-512"],
        &[NamedOid::new(
            &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x03],
            "1.2.643.7.1.1.2.3",
            "id-tc26-gost3411-12-512",
        )],
        || Box::new(tc_gost3411::Gost3411_2012_512Digest::new()),
    ),
    #[cfg(feature = "ripemd128")]
    DigestEntry::new(
        &["RIPEMD128", "RIPEMD-128"],
        &[NamedOid::new(
            &[0x2b, 0x24, 0x03, 0x02, 0x02],
            "1.3.36.3.2.2",
            "RipeMD128",
        )],
        || Box::new(tc_ripemd::RipeMd128Digest::new()),
    ),
    #[cfg(feature = "ripemd160")]
    DigestEntry::new(
        &["RIPEMD160", "RIPEMD-160"],
        &[NamedOid::new(
            &[0x2b, 0x24, 0x03, 0x02, 0x01],
            "1.3.36.3.2.1",
            "RipeMD160",
        )],
        || Box::new(tc_ripemd::RipeMd160Digest::new()),
    ),
    #[cfg(feature = "ripemd256")]
    DigestEntry::new(
        &["RIPEMD256", "RIPEMD-256"],
        &[NamedOid::new(
            &[0x2b, 0x24, 0x03, 0x02, 0x03],
            "1.3.36.3.2.3",
            "RipeMD256",
        )],
        || Box::new(tc_ripemd::RipeMd256Digest::new()),
    ),
    // Bouncy Castle leaves RIPEMD-320 without an OID
    #[cfg(feature = "ripemd320")]
    DigestEntry::new(&["RIPEMD320", "RIPEMD-320"], &[], || {
        Box::new(tc_ripemd::RipeMd320Digest::new())
    }),
    #[cfg(feature = "sm3")]
    DigestEntry::new(
        &["SM3"],
        &[NamedOid::new(
            &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x11],
            "1.2.156.10197.1.401",
            "sm3",
        )],
        || Box::new(tc_sm3::Sm3Digest::new()),
    ),
    #[cfg(feature = "tiger")]
    DigestEntry::new(&["TIGER"], &[], || {
        Box::new(tc_misc_digest::TigerDigest::new())
    }),
    #[cfg(feature = "whirlpool")]
    DigestEntry::new(&["WHIRLPOOL"], &[], || {
        Box::new(tc_misc_digest::WhirlpoolDigest::new())
    }),
    #[cfg(feature = "skein-256-128")]
    DigestEntry::new(&["SKEIN-256-128"], &[], || {
        Box::new(tc_skein::SkeinDigest::new(256, 128))
    }),
    #[cfg(feature = "skein-256-160")]
    DigestEntry::new(&["SKEIN-256-160"], &[], || {
        Box::new(tc_skein::SkeinDigest::new(256, 160))
    }),
    #[cfg(feature = "skein-256-224")]
    DigestEntry::new(&["SKEIN-256-224"], &[], || {
        Box::new(tc_skein::SkeinDigest::new(256, 224))
    }),
    #[cfg(feature = "skein-256-256")]
    DigestEntry::new(&["SKEIN-256-256"], &[], || {
        Box::new(tc_skein::SkeinDigest::new(256, 256))
    }),
    #[cfg(feature = "skein-512-128")]
    DigestEntry::new(&["SKEIN-512-128"], &[], || {
        Box::new(tc_skein::SkeinDigest::new(512, 128))
    }),
    #[cfg(feature = "skein-512-160")]
    DigestEntry::new(&["SKEIN-512-160"], &[], || {
        Box::new(tc_skein::SkeinDigest::new(512, 160))
    }),
    #[cfg(feature = "skein-512-224")]
    DigestEntry::new(&["SKEIN-512-224"], &[], || {
        Box::new(tc_skein::SkeinDigest::new(512, 224))
    }),
    #[cfg(feature = "skein-512-256")]
    DigestEntry::new(&["SKEIN-512-256"], &[], || {
        Box::new(tc_skein::SkeinDigest::new(512, 256))
    }),
    #[cfg(feature = "skein-512-384")]
    DigestEntry::new(&["SKEIN-512-384"], &[], || {
        Box::new(tc_skein::SkeinDigest::new(512, 384))
    }),
    #[cfg(feature = "skein-512-512")]
    DigestEntry::new(&["SKEIN-512-512"], &[], || {
        Box::new(tc_skein::SkeinDigest::new(512, 512))
    }),
    #[cfg(feature = "skein-1024-384")]
    DigestEntry::new(&["SKEIN-1024-384"], &[], || {
        Box::new(tc_skein::SkeinDigest::new(1024, 384))
    }),
    #[cfg(feature = "skein-1024-512")]
    DigestEntry::new(&["SKEIN-1024-512"], &[], || {
        Box::new(tc_skein::SkeinDigest::new(1024, 512))
    }),
    #[cfg(feature = "skein-1024-1024")]
    DigestEntry::new(&["SKEIN-1024-1024"], &[], || {
        Box::new(tc_skein::SkeinDigest::new(1024, 1024))
    }),
    #[cfg(feature = "esch-256")]
    DigestEntry::new(&["ESCH-256"], &[], || {
        Box::new(tc_misc_digest::SparkleDigest::new(
            tc_misc_digest::SparkleParameters::Esch256,
        ))
    }),
    #[cfg(feature = "esch-384")]
    DigestEntry::new(&["ESCH-384"], &[], || {
        Box::new(tc_misc_digest::SparkleDigest::new(
            tc_misc_digest::SparkleParameters::Esch384,
        ))
    }),
    #[cfg(feature = "xoodyak")]
    DigestEntry::new(&["XOODYAK", "XOODYAK HASH"], &[], || {
        Box::new(tc_misc_digest::XoodyakDigest::new())
    }),
    #[cfg(feature = "photon-beetle")]
    DigestEntry::new(&["PHOTON-BEETLE", "PHOTON-BEETLE HASH"], &[], || {
        Box::new(tc_misc_digest::PhotonBeetleDigest::new())
    }),
    #[cfg(feature = "ascon-hash256")]
    DigestEntry::new(&["ASCON-HASH256"], &[], || {
        Box::new(tc_ascon_hash::AsconHash256::new())
    }),
    #[cfg(feature = "ascon-hash-legacy")]
    DigestEntry::new(&["ASCON-HASH"], &[], ascon_hash),
    #[cfg(feature = "ascon-hash-legacy")]
    DigestEntry::new(&["ASCON-HASHA"], &[], ascon_hasha),
    #[cfg(feature = "isap")]
    DigestEntry::new(&["ISAP", "ISAP HASH"], &[], || {
        Box::new(tc_ascon_hash::IsapDigest::new())
    }),
    #[cfg(feature = "haraka")]
    DigestEntry::new(&["HARAKA-256"], &[], || {
        Box::new(super::fixed_input::FixedInput(
            tc_misc_digest::Haraka256Digest::new(),
        ))
    }),
    #[cfg(feature = "haraka")]
    DigestEntry::new(&["HARAKA-512"], &[], || {
        Box::new(super::fixed_input::FixedInput(
            tc_misc_digest::Haraka512Digest::new(),
        ))
    }),
    #[cfg(feature = "null-digest")]
    DigestEntry::new(&["NONE"], &[], || {
        Box::new(tc_digest::util::NullDigest::new())
    }),
];
