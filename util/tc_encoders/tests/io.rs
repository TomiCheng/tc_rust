#![cfg(feature = "std")]

use std::io::Cursor;

use tc_encoders::Encoder;
use tc_encoders::hex::Hex;

#[test]
fn hex_reads_from_a_reader_and_writes_to_a_writer_through_the_default_methods() {
    let mut encoded = Vec::new();
    let mut input: &[u8] = &[0xca, 0xfe];
    assert_eq!(Hex::LOWER.encode_from(&mut input, &mut encoded).unwrap(), 4);
    assert_eq!(encoded, b"cafe");

    let mut decoded = Vec::new();
    let len = Hex::LOWER
        .decode_from(&mut Cursor::new(b"ca fe\n"), &mut decoded)
        .unwrap();
    assert_eq!((len, decoded), (2, vec![0xca, 0xfe]));

    let error = Hex::LOWER.decode_to(b"zz", &mut Vec::new()).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}
