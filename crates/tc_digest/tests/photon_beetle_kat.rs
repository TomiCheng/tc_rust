//! Official PHOTON-Beetle-Hash known-answer tests (NIST LWC
//! `LWC_HASH_KAT_256.txt`, 1025 vectors: Msg → 32-byte MD).

use tc_crypto_core::Digest;
use tc_digest::PhotonBeetleDigest;

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// PHOTON-Beetle 的 rate-4 nibble 置換在 debug 下很慢(全 1025 條約 1.5 分),
// 故標 ignore;預設由 src 的 known_vectors 快速驗證。用
// `cargo test -p tc_digest --test photon_beetle_kat -- --ignored`(建議加 --release)跑完整。
#[test]
#[ignore = "slow in debug; run explicitly, ideally with --release"]
fn official_photon_beetle_hash_kat() {
    let data = include_str!("data/photon_beetle_kat.txt");
    let (mut msg, mut md, mut count) = (None, None, 0usize);
    let mut checked = 0usize;

    for line in data.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("Msg =") {
            msg = Some(unhex(v));
        } else if let Some(v) = line.strip_prefix("MD =") {
            md = Some(unhex(v));
        } else if let Some(v) = line.strip_prefix("Count =") {
            count = v.trim().parse().unwrap();
        }

        if let (Some(m), Some(expected)) = (&msg, &md) {
            let mut d = PhotonBeetleDigest::new();
            d.update(m);
            let mut out = [0u8; 32];
            d.do_final(&mut out);
            assert_eq!(&out[..], &expected[..], "Count {count}: single-shot");

            let mut d = PhotonBeetleDigest::new();
            for chunk in m.chunks(3) {
                d.update(chunk);
            }
            let mut out = [0u8; 32];
            d.do_final(&mut out);
            assert_eq!(&out[..], &expected[..], "Count {count}: chunked");

            checked += 1;
            (msg, md) = (None, None);
        }
    }
    assert_eq!(checked, 1025);
}
