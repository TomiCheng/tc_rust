//! RC6-32/20 agrees with RustCrypto for every accepted key length.

mod common;

use cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit, typenum::*};
use common::unhex;
use rc6::{RC6, RC6_32_20_16};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
use tc_rc6_v2::{BLOCK_BYTES, Rc6Engine};

fn reference_block(key: &[u8; 16], input: [u8; 16], direction: CipherDirection) -> [u8; 16] {
    let reference = RC6_32_20_16::new(&(*key).into());
    let mut block = input.into();
    match direction {
        CipherDirection::Encrypt => reference.encrypt(From::from(&mut block)),
        CipherDirection::Decrypt => reference.decrypt(From::from(&mut block)),
    }
    block.into()
}

macro_rules! compare_pairs {
    ($size:ty) => {{
        type Reference = RC6<u32, U20, $size>;
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed as u8
        };
        for _ in 0..64 {
            let key: Vec<u8> = (0..<$size>::USIZE).map(|_| next()).collect();
            let input: [u8; BLOCK_BYTES] = core::array::from_fn(|_| next());
            let reference = Reference::new_from_slice(&key).unwrap();
            for direction in [CipherDirection::Encrypt, CipherDirection::Decrypt] {
                let mut expected = Block::<Reference>::from(input);
                match direction {
                    CipherDirection::Encrypt => reference.encrypt_block(&mut expected),
                    CipherDirection::Decrypt => reference.decrypt_block(&mut expected),
                }
                let mut engine = Rc6Engine::new();
                engine.init(direction, &KeyRef::new(&key)).unwrap();
                let mut actual = [0; BLOCK_BYTES];
                engine.process_block(&input, &mut actual).unwrap();
                assert_eq!(actual.as_slice(), expected.as_slice());
            }
        }
    }};
}

#[test]
fn rc6_matches_a_known_answer_then_64_pairs_for_every_accepted_key_length() {
    let key = [0; 16];
    let plaintext: [u8; BLOCK_BYTES] = unhex("80000000000000000000000000000000")
        .try_into()
        .unwrap();
    let ciphertext: [u8; BLOCK_BYTES] = unhex("f71f65e7b80c0c6966fee607984b5cdf")
        .try_into()
        .unwrap();
    assert_eq!(
        reference_block(&key, plaintext, CipherDirection::Encrypt),
        ciphertext
    );
    assert_eq!(
        reference_block(&key, ciphertext, CipherDirection::Decrypt),
        plaintext
    );

    compare_pairs!(U1);
    compare_pairs!(U2);
    compare_pairs!(U3);
    compare_pairs!(U4);
    compare_pairs!(U5);
    compare_pairs!(U6);
    compare_pairs!(U7);
    compare_pairs!(U8);
    compare_pairs!(U9);
    compare_pairs!(U10);
    compare_pairs!(U11);
    compare_pairs!(U12);
    compare_pairs!(U13);
    compare_pairs!(U14);
    compare_pairs!(U15);
    compare_pairs!(U16);
    compare_pairs!(U17);
    compare_pairs!(U18);
    compare_pairs!(U19);
    compare_pairs!(U20);
    compare_pairs!(U21);
    compare_pairs!(U22);
    compare_pairs!(U23);
    compare_pairs!(U24);
    compare_pairs!(U25);
    compare_pairs!(U26);
    compare_pairs!(U27);
    compare_pairs!(U28);
    compare_pairs!(U29);
    compare_pairs!(U30);
    compare_pairs!(U31);
    compare_pairs!(U32);
    compare_pairs!(U33);
    compare_pairs!(U34);
    compare_pairs!(U35);
    compare_pairs!(U36);
    compare_pairs!(U37);
    compare_pairs!(U38);
    compare_pairs!(U39);
    compare_pairs!(U40);
    compare_pairs!(U41);
    compare_pairs!(U42);
    compare_pairs!(U43);
    compare_pairs!(U44);
    compare_pairs!(U45);
    compare_pairs!(U46);
    compare_pairs!(U47);
    compare_pairs!(U48);
    compare_pairs!(U49);
    compare_pairs!(U50);
    compare_pairs!(U51);
    compare_pairs!(U52);
    compare_pairs!(U53);
    compare_pairs!(U54);
    compare_pairs!(U55);
    compare_pairs!(U56);
    compare_pairs!(U57);
    compare_pairs!(U58);
    compare_pairs!(U59);
    compare_pairs!(U60);
    compare_pairs!(U61);
    compare_pairs!(U62);
    compare_pairs!(U63);
    compare_pairs!(U64);
    compare_pairs!(U65);
    compare_pairs!(U66);
    compare_pairs!(U67);
    compare_pairs!(U68);
    compare_pairs!(U69);
    compare_pairs!(U70);
    compare_pairs!(U71);
    compare_pairs!(U72);
    compare_pairs!(U73);
    compare_pairs!(U74);
    compare_pairs!(U75);
    compare_pairs!(U76);
    compare_pairs!(U77);
    compare_pairs!(U78);
    compare_pairs!(U79);
    compare_pairs!(U80);
    compare_pairs!(U81);
    compare_pairs!(U82);
    compare_pairs!(U83);
    compare_pairs!(U84);
    compare_pairs!(U85);
    compare_pairs!(U86);
    compare_pairs!(U87);
    compare_pairs!(U88);
    compare_pairs!(U89);
    compare_pairs!(U90);
    compare_pairs!(U91);
    compare_pairs!(U92);
    compare_pairs!(U93);
    compare_pairs!(U94);
    compare_pairs!(U95);
    compare_pairs!(U96);
    compare_pairs!(U97);
    compare_pairs!(U98);
    compare_pairs!(U99);
    compare_pairs!(U100);
    compare_pairs!(U101);
    compare_pairs!(U102);
    compare_pairs!(U103);
    compare_pairs!(U104);
    compare_pairs!(U105);
    compare_pairs!(U106);
    compare_pairs!(U107);
    compare_pairs!(U108);
    compare_pairs!(U109);
    compare_pairs!(U110);
    compare_pairs!(U111);
    compare_pairs!(U112);
    compare_pairs!(U113);
    compare_pairs!(U114);
    compare_pairs!(U115);
    compare_pairs!(U116);
    compare_pairs!(U117);
    compare_pairs!(U118);
    compare_pairs!(U119);
    compare_pairs!(U120);
    compare_pairs!(U121);
    compare_pairs!(U122);
    compare_pairs!(U123);
    compare_pairs!(U124);
    compare_pairs!(U125);
    compare_pairs!(U126);
    compare_pairs!(U127);
    compare_pairs!(U128);
    compare_pairs!(U129);
    compare_pairs!(U130);
    compare_pairs!(U131);
    compare_pairs!(U132);
    compare_pairs!(U133);
    compare_pairs!(U134);
    compare_pairs!(U135);
    compare_pairs!(U136);
    compare_pairs!(U137);
    compare_pairs!(U138);
    compare_pairs!(U139);
    compare_pairs!(U140);
    compare_pairs!(U141);
    compare_pairs!(U142);
    compare_pairs!(U143);
    compare_pairs!(U144);
    compare_pairs!(U145);
    compare_pairs!(U146);
    compare_pairs!(U147);
    compare_pairs!(U148);
    compare_pairs!(U149);
    compare_pairs!(U150);
    compare_pairs!(U151);
    compare_pairs!(U152);
    compare_pairs!(U153);
    compare_pairs!(U154);
    compare_pairs!(U155);
    compare_pairs!(U156);
    compare_pairs!(U157);
    compare_pairs!(U158);
    compare_pairs!(U159);
    compare_pairs!(U160);
    compare_pairs!(U161);
    compare_pairs!(U162);
    compare_pairs!(U163);
    compare_pairs!(U164);
    compare_pairs!(U165);
    compare_pairs!(U166);
    compare_pairs!(U167);
    compare_pairs!(U168);
    compare_pairs!(U169);
    compare_pairs!(U170);
    compare_pairs!(U171);
    compare_pairs!(U172);
    compare_pairs!(U173);
    compare_pairs!(U174);
    compare_pairs!(U175);
    compare_pairs!(U176);
    compare_pairs!(U177);
    compare_pairs!(U178);
    compare_pairs!(U179);
    compare_pairs!(U180);
    compare_pairs!(U181);
    compare_pairs!(U182);
    compare_pairs!(U183);
    compare_pairs!(U184);
    compare_pairs!(U185);
    compare_pairs!(U186);
    compare_pairs!(U187);
    compare_pairs!(U188);
    compare_pairs!(U189);
    compare_pairs!(U190);
    compare_pairs!(U191);
    compare_pairs!(U192);
    compare_pairs!(U193);
    compare_pairs!(U194);
    compare_pairs!(U195);
    compare_pairs!(U196);
    compare_pairs!(U197);
    compare_pairs!(U198);
    compare_pairs!(U199);
    compare_pairs!(U200);
    compare_pairs!(U201);
    compare_pairs!(U202);
    compare_pairs!(U203);
    compare_pairs!(U204);
    compare_pairs!(U205);
    compare_pairs!(U206);
    compare_pairs!(U207);
    compare_pairs!(U208);
    compare_pairs!(U209);
    compare_pairs!(U210);
    compare_pairs!(U211);
    compare_pairs!(U212);
    compare_pairs!(U213);
    compare_pairs!(U214);
    compare_pairs!(U215);
    compare_pairs!(U216);
    compare_pairs!(U217);
    compare_pairs!(U218);
    compare_pairs!(U219);
    compare_pairs!(U220);
    compare_pairs!(U221);
    compare_pairs!(U222);
    compare_pairs!(U223);
    compare_pairs!(U224);
    compare_pairs!(U225);
    compare_pairs!(U226);
    compare_pairs!(U227);
    compare_pairs!(U228);
    compare_pairs!(U229);
    compare_pairs!(U230);
    compare_pairs!(U231);
    compare_pairs!(U232);
    compare_pairs!(U233);
    compare_pairs!(U234);
    compare_pairs!(U235);
    compare_pairs!(U236);
    compare_pairs!(U237);
    compare_pairs!(U238);
    compare_pairs!(U239);
    compare_pairs!(U240);
    compare_pairs!(U241);
    compare_pairs!(U242);
    compare_pairs!(U243);
    compare_pairs!(U244);
    compare_pairs!(U245);
    compare_pairs!(U246);
    compare_pairs!(U247);
    compare_pairs!(U248);
    compare_pairs!(U249);
    compare_pairs!(U250);
    compare_pairs!(U251);
    compare_pairs!(U252);
    compare_pairs!(U253);
    compare_pairs!(U254);
    compare_pairs!(U255);
}
