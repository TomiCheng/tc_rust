//! 確認常數時間模冪的內圈不隨指數位元數增加配置。
//!
//! `pow_ct` 走完指數的每一個位元，每個位元做一次平方與一次乘法。若這些中間值
//! 各自配置一次，RSA-2048 的一次 CRT 運算就會產生數千次配置，而且因為
//! `PaddedBigUint` 是 `ZeroizeOnDrop`，每次釋放還要多一趟 memset。
//!
//! 這個測試獨立成一個執行檔，好讓全域配置計數器不被其他測試的配置干擾。

#![cfg(feature = "alloc")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use tc_bigint::modular::{PaddedMontyForm, PaddedMontyParams};
use tc_bigint::{Odd, PaddedBigUint, limbs_for_bits};

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

/// 轉呼叫系統配置器，只多記一筆次數。
struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// 執行 `action` 期間發生的配置次數。
fn allocations_during(action: impl FnOnce()) -> usize {
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    action();
    ALLOCATIONS.load(Ordering::Relaxed) - before
}

/// 高位與最低位都設起來的位元組，湊出一個滿寬的奇模數。
fn odd_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0x5A_u8; len];
    bytes[0] |= 0x80;
    bytes[len - 1] |= 1;
    bytes
}

#[test]
fn the_constant_time_power_does_not_allocate_per_exponent_bit() {
    let width = limbs_for_bits(256);
    let modulus = PaddedBigUint::from_be_bytes(&odd_bytes(32), width).unwrap();
    let params = PaddedMontyParams::new(Odd::new(modulus).unwrap());

    let base = PaddedMontyForm::new_ct(
        &PaddedBigUint::from_be_bytes(&[7], width).unwrap(),
        params.clone(),
    );

    // 兩個指數的數值相同，只有儲存寬度不同 —— 一個跑 64 圈，一個跑 256 圈。
    let narrow_exponent = PaddedBigUint::from_be_bytes(&[0x9B], limbs_for_bits(64)).unwrap();
    let wide_exponent = PaddedBigUint::from_be_bytes(&[0x9B], width).unwrap();

    let narrow = allocations_during(|| {
        let _ = base.pow_ct(&narrow_exponent);
    });
    let wide = allocations_during(|| {
        let _ = base.pow_ct(&wide_exponent);
    });

    // 圈數差了將近 200，配置次數不該跟著走。
    assert!(
        wide.abs_diff(narrow) < 8,
        "配置次數隨指數位元數成長：{narrow} 圈少的版本，{wide} 圈多的版本"
    );
    // 順帶擋住「常數但很大」的情形。
    assert!(wide < 32, "單次 pow_ct 配置了 {wide} 次");
}
