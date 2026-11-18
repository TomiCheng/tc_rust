#[allow(unused_imports, reason = "unused when no MAC of this file is on")]
use super::row::{Iv, RowMac, named};
use crate::DefaultAlgoContext;
use crate::mac::MacEntry;

// The MACs of their own: ISO 9797-1 algorithm 3 over DES, GOST 28147's MAC, VMPC-MAC and SipHash of
// Bouncy Castle's MacUtilities, and further KMAC, Poly1305 and Skein-MAC
pub(super) fn keyed(_context: &DefaultAlgoContext) -> Vec<Box<dyn MacEntry>> {
    #[allow(unused_mut, reason = "empty when no MAC of this file is on")]
    let mut rows: Vec<Box<dyn MacEntry>> = Vec::new();

    // A key of 16 or 24 bytes, and an IV of 8 bytes or none
    #[cfg(feature = "iso9797-mac")]
    {
        use tc_iso9797_mac::Iso9797Alg3Mac;
        rows.push(named(
            "ISO9797ALG3MAC",
            &["ISO9797ALG3", "DESWITHISO9797", "DESISO9797MAC"],
            &[],
            || Box::new(RowMac::new(Iso9797Alg3Mac::new(), Iv::Optional(8))),
        ));
        rows.push(named(
            "ISO9797ALG3WITHISO7816-4PADDING",
            &["ISO9797ALG3MACWITHISO7816-4PADDING"],
            &[],
            || {
                Box::new(RowMac::new(
                    Iso9797Alg3Mac::with_padding(tc_block_padding::Iso7816d4Padding::new()),
                    Iv::Optional(8),
                ))
            },
        ));
    }
    // A key of 32 bytes with the default S-box, or Gost28147ParamsOwned, and an IV of 8 bytes or none
    #[cfg(feature = "gost28147-mac")]
    rows.push(named("GOST28147MAC", &["GOST28147"], &[], || {
        Box::new(RowMac::new(
            tc_gost28147_mac::Gost28147Mac::new(),
            Iv::Optional(8),
        ))
    }));
    #[cfg(feature = "macs")]
    rows.push(named("VMPCMAC", &["VMPC", "VMPC-MAC"], &[], || {
        Box::new(RowMac::new(tc_macs::VmpcMac::new(), Iv::Required))
    }));
    #[cfg(feature = "macs")]
    {
        rows.push(named("SIPHASH-2-4", &["SIPHASH"], &[], || {
            Box::new(RowMac::new(tc_macs::SipHash::new(), Iv::None))
        }));
        rows.push(named("SIPHASH-4-8", &[], &[], || {
            Box::new(RowMac::new(tc_macs::SipHash::with_rounds(4, 8), Iv::None))
        }));
    }
    // With an empty customization string, and the tag of NIST SP 800-185's default: 32 and 64 bytes
    #[cfg(feature = "kmac")]
    {
        rows.push(named("KMAC128", &[], &["2.16.840.1.101.3.4.2.19"], || {
            Box::new(RowMac::new(tc_kmac::KMac::new(128, &[]), Iv::None))
        }));
        rows.push(named("KMAC256", &[], &["2.16.840.1.101.3.4.2.20"], || {
            Box::new(RowMac::new(tc_kmac::KMac::new(256, &[]), Iv::None))
        }));
    }
    #[cfg(feature = "poly1305")]
    rows.push(named("POLY1305", &[], &[], || {
        Box::new(RowMac::new(tc_poly1305::Poly1305::new(), Iv::None))
    }));
    // SKEIN-MAC-<state>-<tag>, in bits, as Bouncy Castle's provider names them
    #[cfg(feature = "skein-mac")]
    {
        macro_rules! skein {
            ($($state:literal - $output:literal),*) => {$(
                rows.push(named(
                    concat!("SKEIN-MAC-", $state, "-", $output),
                    &[concat!("SKEINMAC-", $state, "-", $output)],
                    &[],
                    || Box::new(RowMac::new(tc_skein_mac::SkeinMac::new($state, $output), Iv::None)),
                ));
            )*};
        }
        skein!(
            256 - 128,
            256 - 160,
            256 - 224,
            256 - 256,
            512 - 128,
            512 - 160,
            512 - 224,
            512 - 256,
            512 - 384,
            512 - 512,
            1024 - 384,
            1024 - 512,
            1024 - 1024
        );
    }

    rows
}

#[cfg(all(
    test,
    feature = "iso9797-mac",
    feature = "macs",
    feature = "kmac",
    feature = "poly1305"
))]
mod tests {
    use crate::params::KeyOwned;
    use crate::{AlgoBuilder, DefaultAlgoBuilder};

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    // Bouncy Castle's MacTest
    #[test]
    fn iso9797_algorithm_3_gives_the_tag_of_bouncy_castle() {
        let algo = DefaultAlgoBuilder::default().build();
        let macs = algo.mac();
        let key = KeyOwned::new(unhex("7CA110454A1A6E570131D9619DC1376E"));
        let tag = macs
            .calculate_by_name("ISO9797ALG3", &key, b"Hello World !!!!")
            .unwrap();
        assert_eq!(hex(&tag), "f09b856213bab83b");

        let padded = macs
            .calculate_by_name("ISO9797ALG3WITHISO7816-4PADDING", &key, b"Hello")
            .unwrap();
        let alias = macs
            .calculate_by_name("ISO9797ALG3MACWITHISO7816-4PADDING", &key, b"Hello")
            .unwrap();
        assert_eq!(padded, alias);
    }

    // The vector of the SipHash paper, its 64-bit result written little-endian
    #[test]
    fn siphash_gives_the_tag_of_its_paper() {
        let algo = DefaultAlgoBuilder::default().build();
        let key = KeyOwned::new((0..16).collect());
        let message: Vec<u8> = (0..15).collect();
        let tag = algo
            .mac()
            .calculate_by_name("SIPHASH", &key, &message)
            .unwrap();
        assert_eq!(hex(&tag), "e545be4961ca29a1");
    }

    // NIST's KMAC sample 1
    #[test]
    fn kmac128_gives_the_tag_of_nist_sample_1() {
        let algo = DefaultAlgoBuilder::default().build();
        let key = KeyOwned::new((0x40..0x60).collect());
        let oid = "2.16.840.1.101.3.4.2.19".parse().unwrap();
        let tag = algo
            .mac()
            .calculate_by_oid(&oid, &key, &[0, 1, 2, 3])
            .unwrap();
        assert_eq!(
            hex(&tag),
            "e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e"
        );
    }

    // RFC 8439, section 2.5.2
    #[test]
    fn poly1305_gives_the_tag_of_rfc_8439() {
        let algo = DefaultAlgoBuilder::default().build();
        let key = KeyOwned::new(unhex(
            "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
        ));
        let tag = algo
            .mac()
            .calculate_by_name("POLY1305", &key, b"Cryptographic Forum Research Group")
            .unwrap();
        assert_eq!(hex(&tag), "a8061dc1305136c6c22b8baf0c0127a9");
    }
}
