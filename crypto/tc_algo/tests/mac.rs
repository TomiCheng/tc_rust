// The MAC factory's lookups and params, whichever MACs are enabled
use std::sync::LazyLock;

use tc_algo::{Algo, AnyMacParams, ErrorKind, SecretKey};
use tc_asn1::Asn1Oid;

// One instance for the whole file, so that its tables are built once
#[allow(
    dead_code,
    reason = "unused when the features of the tests here are off"
)]
static ALGO: LazyLock<Algo> = LazyLock::new(Algo::new);

fn params() -> AnyMacParams {
    AnyMacParams::new(SecretKey::new(vec![0x42; 16]))
}

#[test]
fn an_unknown_name_or_oid_is_an_unknown_mac() {
    let by_name = ALGO.mac().get_by_name("NO-SUCH-MAC").unwrap_err();
    assert_eq!(by_name.kind(), ErrorKind::UnknownMac);
    assert_eq!(by_name.to_string(), "unknown MAC");

    let oid: Asn1Oid = "1.2.3.4.5".parse().unwrap();
    assert_eq!(
        ALGO.mac().get_by_oid(&oid).unwrap_err().kind(),
        ErrorKind::UnknownMac
    );
    // A dotted OID is also accepted where a name is, as in Bouncy Castle
    assert_eq!(
        ALGO.mac().get_by_name("1.2.3.4.5").unwrap_err().kind(),
        ErrorKind::UnknownMac
    );
}

#[test]
fn calculate_reports_an_unknown_mac() {
    assert_eq!(
        ALGO.mac()
            .calculate("NO-SUCH-MAC", &params(), b"message")
            .unwrap_err()
            .kind(),
        ErrorKind::UnknownMac
    );
}

#[test]
fn the_params_hold_the_key_and_the_optional_iv_as_given() {
    let plain = params();
    assert_eq!(plain.key().key, [0x42; 16]);
    assert_eq!(plain.iv(), None);

    let with_iv = params().with_iv(vec![1, 2, 3]);
    assert_eq!(with_iv.iv(), Some(&[1, 2, 3][..]));

    let from_key: AnyMacParams = SecretKey::new(vec![7; 8]).into();
    assert_eq!(from_key.key().key, [7; 8]);
    assert_eq!(from_key.iv(), None);
}

#[test]
fn the_params_debug_never_shows_the_key() {
    let debug = format!("{:?}", params());
    assert!(!debug.contains("66"), "{debug}");
}
