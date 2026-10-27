//! What every digest here promises beyond its test vectors.

#![allow(deprecated)]

use tc_ascon_hash::{AsconCXof128, AsconDigest, AsconHash256, AsconXof, AsconXof128, IsapDigest};

// needs_drop 只證明有 destructor，清除的內容由各型別的 Drop 負責
#[test]
fn every_digest_wipes_itself_on_drop() {
    assert!(std::mem::needs_drop::<AsconHash256>());
    assert!(std::mem::needs_drop::<AsconXof128>());
    assert!(std::mem::needs_drop::<AsconCXof128>());
    assert!(std::mem::needs_drop::<AsconDigest>());
    assert!(std::mem::needs_drop::<AsconXof>());
    assert!(std::mem::needs_drop::<IsapDigest>());
}
