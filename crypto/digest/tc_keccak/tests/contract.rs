//! do_final 先檢查輸出長度、再動狀態：太短的緩衝區會 panic，digest 留在原狀態仍可用。
//! 輸入或輸出怎麼切段，都不影響結果。

use std::panic::{AssertUnwindSafe, catch_unwind};

use tc_digest::{Digest, TryDigest, Xof};
use tc_keccak::{CShakeDigest, KeccakDigest, ParallelHash, Sha3Digest, ShakeDigest, TupleHash};

// 逐 byte 餵入一定走單 byte 的路徑，當作對照
#[test]
fn absorbing_in_any_chunks_matches_absorbing_byte_by_byte() {
    let message: Vec<u8> = (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
    for bits in [224, 256, 384, 512] {
        let mut reference = Sha3Digest::new(bits);
        for byte in &message {
            reference.update(core::slice::from_ref(byte));
        }
        let mut want = vec![0; reference.digest_size()];
        reference.do_final(&mut want);

        for chunk in 1..=17 {
            let mut digest = Sha3Digest::new(bits);
            for piece in message.chunks(chunk) {
                digest.update(piece);
            }
            let mut got = vec![0; digest.digest_size()];
            digest.do_final(&mut got);
            assert_eq!(got, want, "SHA3-{bits} in {chunk}-byte chunks");
        }
    }
}

#[test]
fn squeezing_in_any_chunks_matches_squeezing_byte_by_byte() {
    for bits in [128, 256] {
        let mut reference = ShakeDigest::new(bits);
        reference.update(b"abc");
        let want: Vec<u8> = (0..600)
            .map(|_| {
                let mut byte = [0];
                reference.output(&mut byte);
                byte[0]
            })
            .collect();

        for chunk in 1..=17 {
            let mut shake = ShakeDigest::new(bits);
            shake.update(b"abc");
            let mut got = vec![0; want.len()];
            for piece in got.chunks_mut(chunk) {
                shake.output(piece);
            }
            assert_eq!(got, want, "SHAKE{bits} in {chunk}-byte chunks");
        }
    }
}

fn short_output_panics_without_changing_state<D: Digest>(name: &str, make: impl Fn() -> D) {
    let mut expected = make();
    expected.update(b"abc");
    let mut want = vec![0; expected.digest_size()];
    expected.do_final(&mut want);

    let mut digest = make();
    digest.update(b"abc");
    let mut short = vec![0; digest.digest_size() - 1];
    let result = catch_unwind(AssertUnwindSafe(|| digest.do_final(&mut short)));
    assert!(result.is_err(), "{name} accepted a short buffer");

    let mut got = vec![0; digest.digest_size()];
    digest.do_final(&mut got);
    assert_eq!(got, want, "{name}");
}

#[test]
fn every_digest_checks_the_output_length_before_finishing() {
    short_output_panics_without_changing_state("Keccak-256", || KeccakDigest::new(256));
    short_output_panics_without_changing_state("SHA3-256", || Sha3Digest::new(256));
    short_output_panics_without_changing_state("SHAKE128", || ShakeDigest::new(128));
    short_output_panics_without_changing_state("cSHAKE128", || {
        CShakeDigest::new(128, b"", b"Email Signature")
    });
    short_output_panics_without_changing_state("TupleHash128", || TupleHash::new(128, b""));
    short_output_panics_without_changing_state("ParallelHash128", || {
        ParallelHash::new(128, b"", 8)
    });
}

// 清除本身不用 unsafe 看不到；這裡至少確保每個 digest 在 drop 時有事可做
#[test]
fn every_digest_wipes_itself_on_drop() {
    assert!(std::mem::needs_drop::<KeccakDigest>());
    assert!(std::mem::needs_drop::<Sha3Digest>());
    assert!(std::mem::needs_drop::<ShakeDigest>());
    assert!(std::mem::needs_drop::<CShakeDigest>());
    assert!(std::mem::needs_drop::<TupleHash>());
    assert!(std::mem::needs_drop::<ParallelHash>());
}
