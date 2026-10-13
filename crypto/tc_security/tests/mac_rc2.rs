//! MAC 工廠的 RC2MAC：沒有公開的向量，所以用工廠的 RC2/CBC/NOPADDING 加零 IV 算出 CBC-MAC 比對。

#![cfg(feature = "rc2")]

use tc_security::params::AnyParams;
use tc_security::{cipher, mac};

/// BC 的 CbcBlockCipherMac（不補位）：最後不滿一塊時補零、空的訊息補成一整塊零，
/// 以零 IV 做 CBC 加密，tag 取最後一塊的前半。
fn reference_cbc_mac(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut padded = message.to_vec();
    let blocks = message.len().div_ceil(8).max(1);
    padded.resize(blocks * 8, 0);

    let entry = cipher::get_by_name("RC2/CBC/NOPADDING").unwrap();
    let params = AnyParams::new(key.to_vec()).with_iv(vec![0; 8]);
    let sealed = cipher::encrypt(&mut entry.cipher(), &params, &padded).unwrap();
    sealed[sealed.len() - 8..sealed.len() - 4].to_vec()
}

#[test]
fn rc2mac_matches_cbc_mac_computed_with_rc2_cbc() {
    let entry = mac::get_by_name("RC2MAC").unwrap();
    let key: Vec<u8> = (1..=16).collect();
    let params = AnyParams::new(key.clone());
    let mut rc2mac = entry.mac();
    // 空的、不滿一塊、剛好兩塊、兩塊多一點
    for len in [0, 5, 16, 21] {
        let message: Vec<u8> = (0..len as u8).collect();
        let tag = mac::calculate(&mut rc2mac, &params, &message).unwrap();
        assert_eq!(tag.len(), 4);
        assert_eq!(tag, reference_cbc_mac(&key, &message), "{len}");
    }
}

#[test]
fn a_key_alone_uses_a_zero_iv_as_in_bc_and_a_given_iv_is_used_as_is() {
    let entry = mac::get_by_name("RC2MAC").unwrap();
    let mut rc2mac = entry.mac();
    let mut tag = |params: AnyParams| mac::calculate(&mut rc2mac, &params, b"message");

    let key_alone = tag(AnyParams::new(vec![7; 16])).unwrap();
    assert_eq!(
        tag(AnyParams::new(vec![7; 16]).with_iv(vec![0; 8])).unwrap(),
        key_alone
    );
    // 自訂 IV 會改變 tag；長度不是一個區塊的 IV 由 init 拒絕
    assert_ne!(
        tag(AnyParams::new(vec![7; 16]).with_iv(vec![1; 8])).unwrap(),
        key_alone
    );
    assert!(tag(AnyParams::new(vec![7; 16]).with_iv(vec![0; 16])).is_err());
}

#[test]
fn rc2mac_is_also_found_as_rc2_as_in_bc() {
    assert_eq!(
        mac::get_by_name("rc2").map(|entry| entry.name()),
        Ok("RC2MAC")
    );
    assert_eq!(mac::get_by_name("RC2MAC").unwrap().to_string(), "RC2MAC");
}
