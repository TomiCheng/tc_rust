//! cipher 工廠的整張表：不論開了哪些演算法，每個組合都能加解密，名稱與 OID 不重複。

// 沒開任何 cipher 演算法時表是空的，沒有東西可測
#![cfg(any(
    feature = "aes",
    feature = "aria",
    feature = "rc2",
    feature = "rc5",
    feature = "rc6",
    feature = "chacha",
    feature = "ascon"
))]

use std::collections::HashSet;

use tc_security::cipher::{self, Algorithm, CipherEntry, Mode, Padding};
use tc_security::params::AnyParams;

/// 組合能用的參數：金鑰取演算法接受的長度，IV 或 nonce 依模式與區塊大小決定。
#[allow(
    unreachable_code,
    reason = "只開沒有模式的 cipher 時，每個演算法都提前回傳"
)]
fn params_for(entry: &CipherEntry) -> AnyParams {
    let key = |len| vec![7; len];
    let iv = |len| vec![9; len];
    // 沒有模式的 cipher 直接給金鑰與 nonce；block cipher 先決定金鑰與區塊大小
    let (key, block) = match entry.algo() {
        #[cfg(feature = "aes")]
        Algorithm::Aes => (key(16), 16),
        #[cfg(feature = "aria")]
        Algorithm::Aria => (key(16), 16),
        #[cfg(feature = "rc2")]
        Algorithm::Rc2 => (key(16), 8),
        #[cfg(feature = "rc5")]
        Algorithm::Rc5 => (key(16), 8),
        #[cfg(feature = "rc5")]
        Algorithm::Rc5_64 => (key(16), 16),
        #[cfg(feature = "rc6")]
        Algorithm::Rc6 => (key(16), 16),
        #[cfg(feature = "chacha")]
        Algorithm::ChaCha => return AnyParams::new(key(32)).with_iv(iv(8)),
        #[cfg(feature = "chacha")]
        Algorithm::ChaCha7539 => return AnyParams::new(key(32)).with_iv(iv(12)),
        #[cfg(feature = "chacha")]
        Algorithm::XChaCha20 => return AnyParams::new(key(32)).with_iv(iv(24)),
        #[cfg(feature = "ascon")]
        Algorithm::AsconAead128 | Algorithm::Ascon128 | Algorithm::Ascon128a => {
            return AnyParams::aead(key(16), 128, iv(16), Vec::new());
        }
        #[cfg(feature = "ascon")]
        Algorithm::Ascon80pq => return AnyParams::aead(key(20), 128, iv(16), Vec::new()),
        _ => panic!("{entry}: add the parameters of this algorithm"),
    };
    match entry.mode().expect("a block cipher entry has a mode") {
        Mode::Ecb => AnyParams::new(key),
        Mode::Cbc | Mode::Cfb | Mode::Ofb | Mode::Ctr => AnyParams::new(key).with_iv(iv(block)),
        Mode::Ccm | Mode::Gcm | Mode::Ocb => AnyParams::aead(key, 128, iv(12), Vec::new()),
        // EAX 的 tag 不能比區塊長
        Mode::Eax => AnyParams::aead(key, block * 8, iv(block), Vec::new()),
        _ => panic!("{entry}: add the parameters of this mode"),
    }
}

#[test]
fn every_listed_combination_encrypts_and_decrypts_a_message() {
    for entry in cipher::algorithms() {
        let params = params_for(entry);
        let mut aes = entry.cipher();
        // 不補位的 ECB、CBC 只能處理整數個區塊
        let unpadded_block_mode = matches!(entry.mode(), Some(Mode::Ecb | Mode::Cbc))
            && entry.padding() == Some(Padding::NoPadding);
        let message: &[u8] = if unpadded_block_mode {
            &[0x5a; 32]
        } else {
            &[0x5a; 37]
        };

        let sealed = cipher::encrypt(&mut aes, &params, message).unwrap();
        assert_eq!(
            cipher::decrypt(&mut aes, &params, &sealed).unwrap(),
            message,
            "{entry}"
        );
    }
}

#[test]
fn every_entry_name_and_oid_is_unique() {
    let mut names = HashSet::new();
    let mut oids = HashSet::new();
    for entry in cipher::algorithms() {
        assert!(names.insert(entry.name()), "{}", entry.name());
        for oid in entry.oids() {
            assert!(oids.insert(oid.dotted()), "{}", oid.dotted());
        }
    }
}
