use tc_asn1::NamedOid;
use tc_macs::Hmac;

use crate::digest::{self, DigestEntry, TryDigest};
use crate::mac::MacEntry;
use crate::mac::dyn_mac::Mapped;
use crate::need::Need;

// tc_macs refuses a shorter block, which leaves out only NONE, which is not a hash
const MIN_BLOCK_BYTES: usize = 16;

// As in Bouncy Castle: HMAC-SHA256, HMAC/SHA256 and HMACSHA256, over any name of the digest
const PREFIXES: [&str; 3] = ["HMAC-", "HMAC/", "HMAC"];

// The OIDs of Bouncy Castle's MacUtilities, by the digest's canonical name
const OIDS: &[(&str, &[NamedOid])] = &[
    (
        "MD5",
        &[NamedOid::new(
            &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x08, 0x01, 0x01],
            "1.3.6.1.5.5.8.1.1",
            "hmacMD5",
        )],
    ),
    (
        "SHA-1",
        &[
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
    ),
    (
        "SHA-224",
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x08],
            "1.2.840.113549.2.8",
            "id-hmacWithSHA224",
        )],
    ),
    (
        "SHA-256",
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09],
            "1.2.840.113549.2.9",
            "id-hmacWithSHA256",
        )],
    ),
    (
        "SHA-384",
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0a],
            "1.2.840.113549.2.10",
            "id-hmacWithSHA384",
        )],
    ),
    (
        "SHA-512",
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0b],
            "1.2.840.113549.2.11",
            "id-hmacWithSHA512",
        )],
    ),
    (
        "SHA-512/224",
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0c],
            "1.2.840.113549.2.12",
            "id-hmacWithSHA512-224",
        )],
    ),
    (
        "SHA-512/256",
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0d],
            "1.2.840.113549.2.13",
            "id-hmacWithSHA512-256",
        )],
    ),
    (
        "SHA3-224",
        &[NamedOid::new(
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0d],
            "2.16.840.1.101.3.4.2.13",
            "id-hmacWithSHA3-224",
        )],
    ),
    (
        "SHA3-256",
        &[NamedOid::new(
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0e],
            "2.16.840.1.101.3.4.2.14",
            "id-hmacWithSHA3-256",
        )],
    ),
    (
        "SHA3-384",
        &[NamedOid::new(
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0f],
            "2.16.840.1.101.3.4.2.15",
            "id-hmacWithSHA3-384",
        )],
    ),
    (
        "SHA3-512",
        &[NamedOid::new(
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x10],
            "2.16.840.1.101.3.4.2.16",
            "id-hmacWithSHA3-512",
        )],
    ),
    (
        "GOST3411-2012-256",
        &[NamedOid::new(
            &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x04, 0x01],
            "1.2.643.7.1.1.4.1",
            "id-tc26-hmac-gost-3411-12-256",
        )],
    ),
    (
        "GOST3411-2012-512",
        &[NamedOid::new(
            &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x04, 0x02],
            "1.2.643.7.1.1.4.2",
            "id-tc26-hmac-gost-3411-12-512",
        )],
    ),
    (
        "RIPEMD160",
        &[NamedOid::new(
            &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x08, 0x01, 0x04],
            "1.3.6.1.5.5.8.1.4",
            "hmacRIPEMD160",
        )],
    ),
    (
        "TIGER",
        &[NamedOid::new(
            &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x08, 0x01, 0x03],
            "1.3.6.1.5.5.8.1.3",
            "hmacTiger",
        )],
    ),
];

// One row per digest enabled, as Bouncy Castle builds an HMAC over whatever digest the name gives
pub(super) fn rows() -> impl Iterator<Item = MacEntry> {
    digest::algorithms()
        .filter(|digest| TryDigest::byte_length(&digest.create()) >= MIN_BLOCK_BYTES)
        .map(row)
}

fn row(digest: &'static DigestEntry) -> MacEntry {
    let names = digest
        .names()
        .iter()
        .flat_map(|name| PREFIXES.map(|prefix| format!("{prefix}{name}")))
        .collect();
    let oids = OIDS
        .iter()
        .find(|(name, _)| *name == digest.name())
        .map_or(&[][..], |(_, oids)| oids);
    MacEntry::new(names, oids, Need::Forbidden, move || {
        Box::new(Mapped::key_only(Hmac::new(digest.create())))
    })
}
