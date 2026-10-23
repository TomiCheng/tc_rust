use tc_pbe::{pkcs5_password_to_bytes, pkcs5_password_to_utf8_bytes, pkcs12_password_to_bytes};

#[test]
fn an_ascii_password_is_the_same_bytes_under_both_pkcs5_encodings() {
    assert_eq!(&pkcs5_password_to_bytes("password")[..], b"password");
    assert_eq!(&pkcs5_password_to_utf8_bytes("password")[..], b"password");
}

#[test]
fn pkcs5_keeps_the_low_byte_of_each_utf16_unit_as_bc_does() {
    // U+00E9 é 留下 0xE9；U+4E2D 中 只剩 0x2D；U+1F600 是兩個 surrogate 0xD83D 0xDE00
    assert_eq!(
        &pkcs5_password_to_bytes("é中😀")[..],
        [0xe9, 0x2d, 0x3d, 0x00]
    );
    assert_eq!(
        &pkcs5_password_to_utf8_bytes("é中")[..],
        [0xc3, 0xa9, 0xe4, 0xb8, 0xad]
    );
}

#[test]
fn pkcs12_is_utf16_big_endian_with_a_two_byte_terminator() {
    assert_eq!(
        &pkcs12_password_to_bytes("ab", false)[..],
        [0x00, 0x61, 0x00, 0x62, 0x00, 0x00]
    );
    assert_eq!(
        &pkcs12_password_to_bytes("é😀", false)[..],
        [0x00, 0xe9, 0xd8, 0x3d, 0xde, 0x00, 0x00, 0x00]
    );
    // 旗標只影響空密碼
    assert_eq!(
        &pkcs12_password_to_bytes("ab", true)[..],
        &pkcs12_password_to_bytes("ab", false)[..]
    );
}

#[test]
fn an_empty_password_gives_no_bytes_unless_bcs_wrong_zero_is_asked_for() {
    assert!(pkcs5_password_to_bytes("").is_empty());
    assert!(pkcs5_password_to_utf8_bytes("").is_empty());
    assert!(pkcs12_password_to_bytes("", false).is_empty());
    assert_eq!(&pkcs12_password_to_bytes("", true)[..], [0x00, 0x00]);
}
