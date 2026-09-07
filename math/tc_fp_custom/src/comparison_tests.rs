use crate::specialized_field::gte;

fn compare_width<const N: usize>() {
    let mut state = 0x91e1_0da5_u32;
    for _ in 0..128 {
        let mut a = [0; N];
        let mut b = [0; N];
        for word in a.iter_mut().chain(b.iter_mut()) {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *word = state;
        }
        assert_eq!(gte(&a, &a).unwrap_u8(), 1);
        assert_eq!(
            gte(&a, &b).unwrap_u8(),
            u8::from(a.iter().rev().cmp(b.iter().rev()).is_ge())
        );
        for index in 0..N {
            let mut changed = a;
            changed[index] ^= 1;
            assert_eq!(
                gte(&a, &changed).unwrap_u8(),
                u8::from(a.iter().rev().cmp(changed.iter().rev()).is_ge())
            );
        }
    }
}

#[test]
fn choice_comparison_matches_little_endian_numeric_order() {
    compare_width::<0>();
    compare_width::<1>();
    compare_width::<8>();
    compare_width::<17>();
    // The highest unequal limb must override the ordering of lower limbs.
    assert_eq!(gte(&[0, 1], &[u32::MAX, 0]).unwrap_u8(), 1);
    assert_eq!(gte(&[u32::MAX, 0], &[0, 1]).unwrap_u8(), 0);
}
