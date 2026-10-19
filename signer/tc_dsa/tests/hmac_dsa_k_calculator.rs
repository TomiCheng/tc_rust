use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_digest::Digest;
use tc_dsa::{DsaKCalculator, HMacDsaKCalculator};
use tc_sha::{Sha256Digest, Sha512Digest};

fn integer(text: &str) -> PaddedBigUint {
    let text = format!("{}{text}", "0".repeat(text.len() % 2));
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect();
    let Ok(value) = <PaddedBigUint as ArrayEncoding<u8>>::from_be(&bytes);
    value
}

fn first_k<D: Digest>(mut digest: D, n: &str, x: &str, message: &[u8]) -> PaddedBigUint {
    let mut hash = [0; 64];
    digest.update(message);
    let length = digest.do_final(&mut hash);

    let mut calculator = HMacDsaKCalculator::new(digest);
    calculator.init(&integer(n), &integer(x), &hash[..length]);
    calculator.next_k()
}

// RFC 6979 A.1.2: a 163-bit q, under the 256 bits of the hash.
#[test]
fn the_detailed_example_of_rfc_6979_gives_its_k() {
    let k = first_k(
        Sha256Digest::new(),
        "4000000000000000000020108A2E0CC0D99F8A5EF",
        "09A4D6792295A7F730FC3F2B49CBC0F62E862272F",
        b"sample",
    );
    assert_eq!(k, integer("23AF4074C90A02B3FE61D286D5C87F425E6BDD81B"));
}

// RFC 6979 A.2.5, P-256; SHA-512 is longer than n and is cut to its leftmost bits.
#[test]
fn p_256_gives_the_k_of_rfc_6979_for_each_message_and_hash() {
    let n = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";
    let x = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";

    assert_eq!(
        first_k(Sha256Digest::new(), n, x, b"sample"),
        integer("A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60")
    );
    assert_eq!(
        first_k(Sha256Digest::new(), n, x, b"test"),
        integer("D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0")
    );
    assert_eq!(
        first_k(Sha512Digest::new(), n, x, b"sample"),
        integer("5FA81C63109BADB88C1F367B47DA606DA28CAD69AA22C4FE6AD7DF73A7173AA5")
    );
}

// With n = 2, three in four candidates fall out of [1, n − 1] and are drawn again.
#[test]
fn a_k_out_of_range_is_drawn_again_until_one_falls_in_it() {
    for message in [&b"a"[..], b"b", b"c", b"d", b"e", b"f", b"g", b"h"] {
        assert_eq!(
            first_k(Sha256Digest::new(), "2", "1", message),
            integer("1")
        );
    }
}

#[test]
#[should_panic(expected = "the calculator is initialized")]
fn a_calculator_refuses_to_draw_before_init() {
    let mut calculator = HMacDsaKCalculator::new(Sha256Digest::new());
    let _: PaddedBigUint = calculator.next_k();
}
