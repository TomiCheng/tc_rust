// What each kind of MAC in the table takes and refuses, and which rows the features leave in
use std::sync::LazyLock;

use tc_algo_old::{Algo, AnyMacParams, ErrorKind, SecretKey};

// One instance for the whole file, so that its tables are built once
#[allow(
    dead_code,
    reason = "unused when the features of the tests here are off"
)]
static ALGO: LazyLock<Algo> = LazyLock::new(Algo::new);

#[allow(dead_code, reason = "unused when the MACs that use it are off")]
fn params(key_len: usize) -> AnyMacParams {
    AnyMacParams::new(SecretKey::new(vec![0x42; key_len]))
}

#[allow(dead_code, reason = "unused when the MACs that use it are off")]
fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

#[allow(dead_code, reason = "unused when the MACs that use it are off")]
fn init_error(name: &str, params: &AnyMacParams) -> ErrorKind {
    let mut mac = ALGO.mac().get_by_name(name).unwrap();
    mac.init(params).unwrap_err().kind()
}

// RFC 4493, examples 1 and 2
#[cfg(all(feature = "cmac", feature = "aes"))]
#[test]
fn aes_cmac_matches_rfc_4493() {
    let params = AnyMacParams::new(SecretKey::new(unhex("2b7e151628aed2a6abf7158809cf4f3c")));
    assert_eq!(
        ALGO.mac().calculate("AESCMAC", &params, b"").unwrap(),
        unhex("bb1d6929e95937287fa37d129b756746")
    );
    assert_eq!(
        ALGO.mac()
            .calculate(
                "AESCMAC",
                &params,
                &unhex("6bc1bee22e409f96e93d7e117393172a")
            )
            .unwrap(),
        unhex("070a16b46b4d4144f79bdd9dd04a287c")
    );
}

#[cfg(all(feature = "cmac", feature = "aes"))]
#[test]
fn cmac_refuses_an_iv_and_a_key_its_cipher_does_not_take() {
    assert_eq!(
        init_error("AESCMAC", &params(16).with_iv(vec![0; 16])),
        ErrorKind::InvalidParams
    );
    assert_eq!(init_error("AESCMAC", &params(15)), ErrorKind::InvalidParams);
}

#[cfg(all(feature = "cmac", feature = "aes"))]
#[test]
fn a_mac_over_a_cipher_refuses_to_run_before_a_successful_init() {
    let mut mac = ALGO.mac().get_by_name("AESCMAC").unwrap();
    assert_eq!(
        mac.update(b"x").unwrap_err().kind(),
        ErrorKind::NotInitialized
    );
    assert_eq!(
        mac.finalize().unwrap_err().kind(),
        ErrorKind::NotInitialized
    );
}

// The example of the SipHash paper, appendix A
#[cfg(feature = "siphash")]
#[test]
fn siphash_matches_its_paper() {
    let key: Vec<u8> = (0..16).collect();
    let message: Vec<u8> = (0..15).collect();
    let tag = ALGO
        .mac()
        .calculate("SIPHASH", &SecretKey::new(key).into(), &message)
        .unwrap();
    assert_eq!(tag, unhex("e545be4961ca29a1"));
}

#[cfg(feature = "siphash")]
#[test]
fn siphash_refuses_an_iv_and_any_key_but_16_bytes() {
    assert_eq!(
        init_error("SIPHASH-2-4", &params(16).with_iv(vec![0; 8])),
        ErrorKind::InvalidParams
    );
    assert_eq!(
        init_error("SIPHASH-2-4", &params(15)),
        ErrorKind::InvalidParams
    );
}

#[cfg(feature = "vmpc-mac")]
#[test]
fn vmpc_mac_requires_an_iv_of_16_to_64_bytes() {
    assert_eq!(init_error("VMPCMAC", &params(16)), ErrorKind::InvalidParams);
    assert_eq!(
        init_error("VMPCMAC", &params(16).with_iv(vec![0; 15])),
        ErrorKind::InvalidParams
    );
    assert_eq!(
        init_error("VMPCMAC", &params(15).with_iv(vec![0; 16])),
        ErrorKind::InvalidParams
    );
    let mut mac = ALGO.mac().get_by_name("VMPC-MAC").unwrap();
    assert!(mac.init(&params(16).with_iv(vec![0; 16])).is_ok());
}

#[cfg(all(feature = "cbc-mac", feature = "des"))]
#[test]
fn cbc_mac_takes_an_iv_of_exactly_one_block_or_none() {
    let mut mac = ALGO.mac().get_by_name("DESMAC").unwrap();
    assert!(mac.init(&params(8)).is_ok());
    assert!(mac.init(&params(8).with_iv(vec![0; 8])).is_ok());
    assert_eq!(
        init_error("DESMAC", &params(8).with_iv(vec![0; 7])),
        ErrorKind::InvalidParams
    );
    assert_eq!(init_error("DESMAC", &params(7)), ErrorKind::InvalidParams);
}

#[cfg(feature = "iso9797-mac")]
#[test]
fn iso9797_takes_a_two_or_three_key_des_key_and_an_iv_of_one_block_or_none() {
    let mut mac = ALGO.mac().get_by_name("ISO9797ALG3").unwrap();
    assert!(mac.init(&params(16)).is_ok());
    assert!(mac.init(&params(24)).is_ok());
    assert!(mac.init(&params(16).with_iv(vec![0; 8])).is_ok());
    assert_eq!(
        init_error("ISO9797ALG3", &params(8)),
        ErrorKind::InvalidParams
    );
    assert_eq!(
        init_error("ISO9797ALG3", &params(16).with_iv(vec![0; 7])),
        ErrorKind::InvalidParams
    );
}

#[cfg(feature = "iso9797-mac")]
#[test]
fn iso9797_reports_its_own_errors_under_the_same_kinds() {
    let mut mac = ALGO.mac().get_by_name("ISO9797ALG3").unwrap();
    assert_eq!(
        mac.update(b"x").unwrap_err().kind(),
        ErrorKind::NotInitialized
    );
    mac.init(&params(16)).unwrap();
    let mut short = [0; 7];
    let error = tc_algo_old::Mac::do_final(&mut mac, &mut short).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::DataLength);
}

#[cfg(feature = "gost28147-mac")]
#[test]
fn gost_mac_takes_a_32_byte_key_and_an_iv_of_one_block_or_none() {
    let mut mac = ALGO.mac().get_by_name("GOST28147").unwrap();
    assert!(mac.init(&params(32)).is_ok());
    assert!(mac.init(&params(32).with_iv(vec![0; 8])).is_ok());
    assert_eq!(
        init_error("GOST28147", &params(16)),
        ErrorKind::InvalidParams
    );
}

// A row is there only when its MAC's feature and its cipher's feature are both on
#[test]
fn a_mac_over_a_cipher_appears_only_with_both_features() {
    let found = |name: &str| ALGO.mac().get_by_name(name).is_ok();
    assert_eq!(
        found("AESCMAC"),
        cfg!(all(feature = "cmac", feature = "aes"))
    );
    assert_eq!(
        found("DESEDECMAC"),
        cfg!(all(feature = "cmac", feature = "desede"))
    );
    assert_eq!(
        found("DESMAC"),
        cfg!(all(feature = "cbc-mac", feature = "des"))
    );
    assert_eq!(
        found("DESMAC/CFB8"),
        cfg!(all(feature = "cfb-mac", feature = "des"))
    );
    assert_eq!(
        found("RC5MAC"),
        cfg!(all(feature = "cbc-mac", feature = "rc5"))
    );
    assert_eq!(found("ISO9797ALG3MAC"), cfg!(feature = "iso9797-mac"));
    assert_eq!(found("GOST28147MAC"), cfg!(feature = "gost28147-mac"));
    assert_eq!(found("VMPCMAC"), cfg!(feature = "vmpc-mac"));
    assert_eq!(found("SIPHASH-2-4"), cfg!(feature = "siphash"));
}
