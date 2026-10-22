//! do_final 先檢查輸出長度、再動狀態：太短的緩衝區會 panic，digest 留在原狀態仍可用。

use std::panic::{AssertUnwindSafe, catch_unwind};

use tc_digest::Digest;
use tc_keccak::{CShakeDigest, KeccakDigest, ParallelHash, Sha3Digest, ShakeDigest, TupleHash};

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
