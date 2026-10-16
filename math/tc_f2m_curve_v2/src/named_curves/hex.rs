pub(super) const fn hex<const N: usize>(text: &str) -> [u8; N] {
    let digits = text.as_bytes();
    assert!(digits.len() == 2 * N, "two hex digits per byte");
    let mut bytes = [0; N];
    let mut i = 0;
    while i < N {
        bytes[i] = nibble(digits[2 * i]) << 4 | nibble(digits[2 * i + 1]);
        i += 1;
    }
    bytes
}

const fn nibble(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'a'..=b'f' => digit - b'a' + 10,
        _ => panic!("a lowercase hex digit"),
    }
}
