use tc_encoders::base64::{DEFAULT, RFC4648_URL, RFC4648_URL_NO_PAD, URL};
use tc_encoders::{Encoder, EncoderError};

#[test]
fn url_variants_swap_the_last_two_symbols_and_differ_only_in_padding() {
    let mut text = [0; 8];
    for (data, standard, bc_url, rfc_url, rfc_url_no_pad) in [
        (
            &[0xfb, 0xff, 0xbf][..],
            &b"+/+/"[..],
            &b"-_-_"[..],
            &b"-_-_"[..],
            &b"-_-_"[..],
        ),
        (&[0xfb, 0xff], b"+/8=", b"-_8.", b"-_8=", b"-_8"),
        (&[0xff], b"/w==", b"_w..", b"_w==", b"_w"),
    ] {
        for (base64, expected) in [
            (DEFAULT, standard),
            (URL, bc_url),
            (RFC4648_URL, rfc_url),
            (RFC4648_URL_NO_PAD, rfc_url_no_pad),
        ] {
            let len = base64.encode(data, &mut text).unwrap();
            assert_eq!(&text[..len], expected);
            let mut back = [0; 3];
            let len = base64.decode(expected, &mut back).unwrap();
            assert_eq!(&back[..len], data);
        }
    }
}

#[test]
fn bc_url_base64_round_trips_every_byte_value() {
    let data: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut text = [0; 344];
    let mut back = [0; 258];
    let len = URL.encode(&data, &mut text).unwrap();
    let symbols = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.";
    assert!(text[..len].iter().all(|c| symbols.contains(c)));
    let len = URL.decode(&text, &mut back).unwrap();
    assert_eq!(back[..len], data);
}

#[test]
fn each_variant_rejects_the_others_symbols_and_padding() {
    let mut buffer = [0; 3];
    for (base64, input) in [
        (URL, &b"+/+/"[..]),
        (DEFAULT, b"-_-_"),
        (URL, b"Zg=="),
        (RFC4648_URL, b"Zg.."),
    ] {
        assert_eq!(
            base64.decode(input, &mut buffer),
            Err(EncoderError::InvalidCharacter),
            "{input:?}"
        );
    }
}
