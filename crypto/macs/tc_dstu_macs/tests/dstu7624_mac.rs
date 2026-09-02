use tc_dstu_macs::{Dstu7624Mac128, Dstu7624Mac512};
use tc_macs::{Mac, MacError, MacInit};
use tc_params::KeyRef;

#[test]
fn matches_the_bouncy_castle_128_bit_block_vector() {
    let key = core::array::from_fn::<_, 16, _>(|index| index as u8);
    let message = core::array::from_fn::<_, 48, _>(|index| (index + 0x20) as u8);
    let mut mac = Dstu7624Mac128::new(128).unwrap();
    mac.init(&KeyRef::new(&key)).unwrap();
    mac.update(&message).unwrap();

    let mut output = [0_u8; 16];
    mac.do_final(&mut output).unwrap();
    assert_eq!(
        output,
        [
            0x12, 0x3b, 0x4e, 0xab, 0x8e, 0x63, 0xec, 0xf3, 0xe6, 0x45, 0xa9, 0x9c, 0x11, 0x15,
            0xe2, 0x41,
        ]
    );
}

#[test]
fn matches_the_bouncy_castle_512_bit_block_vector() {
    let key = core::array::from_fn::<_, 64, _>(|index| index as u8);
    let message = core::array::from_fn::<_, 128, _>(|index| (index + 0x40) as u8);
    let mut mac = Dstu7624Mac512::new(128).unwrap();
    mac.init(&KeyRef::new(&key)).unwrap();
    for chunk in message.chunks(11) {
        mac.update(chunk).unwrap();
    }

    let mut output = [0_u8; 16];
    mac.do_final(&mut output).unwrap();
    assert_eq!(
        output,
        [
            0x72, 0x79, 0xfa, 0x6b, 0xc8, 0xef, 0x75, 0x25, 0xb2, 0xb3, 0x52, 0x60, 0xd0, 0x0a,
            0x17, 0x43,
        ]
    );
}

#[test]
fn rejects_a_partial_final_block_without_losing_it() {
    let key = [0_u8; 16];
    let mut mac = Dstu7624Mac128::new(128).unwrap();
    mac.init(&KeyRef::new(&key)).unwrap();
    mac.update(&[0_u8; 15]).unwrap();
    assert_eq!(
        mac.do_final(&mut [0_u8; 16]),
        Err(MacError::InputNotBlockAligned {
            block_size: 16,
            remainder: 15,
        })
    );
    mac.update(&[0]).unwrap();
    assert_eq!(mac.do_final(&mut [0_u8; 16]), Ok(16));
}
