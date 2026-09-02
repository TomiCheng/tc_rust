use tc_kmac::KMac;
use tc_macs::{Mac, MacInit};
use tc_params::KeyRef;

fn decode(hex: &str) -> Vec<u8> {
    let filtered: Vec<_> = hex.bytes().filter(u8::is_ascii_hexdigit).collect();
    let (pairs, remainder) = filtered.as_chunks::<2>();
    assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => unreachable!(),
            };
            digit(pair[0]) << 4 | digit(pair[1])
        })
        .collect()
}

#[test]
fn matches_nist_and_bouncy_castle_kmac128_vectors() {
    let key = decode("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
    let cases = [
        (
            b"".as_slice(),
            "00010203",
            "e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e",
        ),
        (
            b"My Tagged Application".as_slice(),
            "00010203",
            "3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5",
        ),
    ];

    for (customization, message, expected) in cases {
        let mut kmac = KMac::new(128, customization);
        kmac.init(&KeyRef::new(&key)).unwrap();
        kmac.update(&decode(message)).unwrap();
        let mut output = [0_u8; 32];
        kmac.do_final(&mut output).unwrap();
        assert_eq!(output.as_slice(), decode(expected));
    }
}

#[test]
fn matches_the_bouncy_castle_kmac256_vector() {
    let key = decode("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
    let mut kmac = KMac::new(256, b"My Tagged Application");
    kmac.init(&KeyRef::new(&key)).unwrap();
    kmac.update(&[0, 1, 2, 3]).unwrap();
    let mut output = [0_u8; 64];
    kmac.do_final(&mut output).unwrap();
    assert_eq!(
        output.as_slice(),
        decode(concat!(
            "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7",
            "f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd"
        ))
    );
}

#[test]
fn xof_output_continues_until_output_final_resets() {
    let key = decode("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
    let mut kmac = KMac::new(128, b"My Tagged Application");
    kmac.init(&KeyRef::new(&key)).unwrap();
    kmac.update(&[0, 1, 2, 3]).unwrap();

    let mut first = [0_u8; 32];
    kmac.output(&mut first).unwrap();
    assert_eq!(
        first.as_slice(),
        decode("31a44527b4ed9f5c6101d11de6d26f0620aa5c341def41299657fe9df1a3b16c")
    );

    let mut second = [0_u8; 32];
    kmac.output(&mut second).unwrap();
    assert_ne!(second, first);
    kmac.output_final(&mut second).unwrap();

    kmac.update(&[0, 1, 2, 3]).unwrap();
    kmac.output(&mut first).unwrap();
    assert_eq!(
        first.as_slice(),
        decode("31a44527b4ed9f5c6101d11de6d26f0620aa5c341def41299657fe9df1a3b16c")
    );
}

#[test]
fn key_bytepad_crosses_the_rate_boundary_correctly() {
    let data = decode("01880204187b3e43eda8d51ec181d37dde5b17eccdd8be84c268dc6c9500700857");
    let mut kmac = KMac::new(128, b"");
    kmac.init(&KeyRef::new(&[0_u8; 163])).unwrap();
    kmac.update(&data).unwrap();

    let mut output = [0_u8; 32];
    kmac.output(&mut output).unwrap();
    assert_eq!(
        output.as_slice(),
        decode("6e6ab56468c7445f81c679f89f45c90a95a9c01afbaab5f7065b7e2e96f7d2bb")
    );
}
