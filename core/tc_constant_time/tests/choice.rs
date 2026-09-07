use tc_constant_time::Choice;

#[test]
fn choice_normalizes_every_byte_and_combines_bits() {
    for value in 0..=u8::MAX {
        let choice = Choice::from_lsb(value);
        assert_eq!(choice.unwrap_u8(), value & 1);
        assert_eq!((!choice).unwrap_u8(), (value & 1) ^ 1);
        for bit in 0..=1 {
            let rhs = Choice::from_lsb(bit);
            assert_eq!((choice & rhs).unwrap_u8(), (value & 1) & bit);
            assert_eq!((choice | rhs).unwrap_u8(), (value & 1) | bit);
        }
    }
}
