//! `Sm2KeyExchange`：Bouncy Castle `SM2KeyExchangeTest` 的向量（SM2 草案的 Fp 測試曲線，
//! 以及餘因子為 4 的 F2m 測試曲線），含金鑰確認；以及錯誤。

use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_f2m_curve::{F2mCtCurve, F2mField};
use tc_fp_curve::{FpCtCurve, FpField};
use tc_sm2::{
    Sm2Curve, Sm2Error, Sm2KeyExchange, Sm2KeyExchangePrivateParams, Sm2KeyExchangePublicParams,
};

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn integer(hex: &str) -> PaddedBigUint {
    PaddedBigUint::from_be(&bytes(hex)).unwrap()
}

const ALICE: &[u8] = b"ALICE123@YAHOO.COM";
const BILL: &[u8] = b"BILL456@YAHOO.COM";

/// 一方的長期與臨時金鑰對。
struct Party<C: Sm2Curve> {
    static_private: EcPrivateKey<C>,
    static_public: EcPublicKey<C>,
    ephemeral_private: EcPrivateKey<C>,
    ephemeral_public: EcPublicKey<C>,
}

fn party<C: Sm2Curve>(g: &C::Point, static_d: &str, ephemeral_d: &str) -> Party<C> {
    let pair = |d: &str| {
        let d = integer(d);
        let q = C::multiply(g, &d);
        (
            EcPrivateKey::<C>::new(g.clone(), d).unwrap(),
            EcPublicKey::<C>::new(g.clone(), &q).unwrap(),
        )
    };
    let (static_private, static_public) = pair(static_d);
    let (ephemeral_private, ephemeral_public) = pair(ephemeral_d);
    Party {
        static_private,
        static_public,
        ephemeral_private,
        ephemeral_public,
    }
}

fn exchange<C: Sm2Curve>(me: &Party<C>, initiator: bool, my_id: &[u8]) -> Sm2KeyExchange<C> {
    let mut exchange = Sm2KeyExchange::new();
    exchange
        .init(
            &Sm2KeyExchangePrivateParams::new(
                initiator,
                me.static_private.clone(),
                me.ephemeral_private.clone(),
            )
            .with_user_id(my_id.to_vec()),
        )
        .unwrap();
    exchange
}

fn public<C: Sm2Curve>(other: &Party<C>, other_id: &[u8]) -> Sm2KeyExchangePublicParams<C> {
    Sm2KeyExchangePublicParams::new(other.static_public.clone(), other.ephemeral_public.clone())
        .with_user_id(other_id.to_vec())
}

/// BC 測試的步驟：雙方各自算出 16 位元組的金鑰，再走一次金鑰確認。
fn known_answer<C: Sm2Curve>(
    alice: &Party<C>,
    bill: &Party<C>,
    key: &str,
    tag_from_bill: &str,
    tag_from_alice: &str,
) {
    let mut k1 = [0u8; 16];
    exchange(alice, true, ALICE)
        .calculate_key(&public(bill, BILL), &mut k1)
        .unwrap();
    assert_eq!(k1[..], bytes(key)[..], "initiator key");
    let mut k2 = [0u8; 16];
    exchange(bill, false, BILL)
        .calculate_key(&public(alice, ALICE), &mut k2)
        .unwrap();
    assert_eq!(k2, k1, "responder key");

    let mut responder_key = [0u8; 16];
    let responder = exchange(bill, false, BILL)
        .calculate_key_with_confirmation(None, &public(alice, ALICE), &mut responder_key)
        .unwrap();
    assert_eq!(responder_key, k1);
    assert_eq!(responder.to_send, bytes(tag_from_bill), "S_B");
    assert_eq!(responder.expected, Some(bytes(tag_from_alice)), "S_A");

    let mut initiator_key = [0u8; 16];
    let initiator = exchange(alice, true, ALICE)
        .calculate_key_with_confirmation(
            Some(&responder.to_send),
            &public(bill, BILL),
            &mut initiator_key,
        )
        .unwrap();
    assert_eq!(initiator_key, k1);
    assert_eq!(initiator.to_send, bytes(tag_from_alice));
    assert_eq!(initiator.expected, None);
}

#[test]
fn the_fp_test_curve_matches_bouncy_castle() {
    let field = FpField::new(integer(
        "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",
    ))
    .unwrap();
    let curve = FpCtCurve::new(
        &field,
        &integer("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498"),
        &integer("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A"),
        Some(integer(
            "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",
        )),
        Some(PaddedBigUint::from(1u8)),
    )
    .unwrap();
    let g = curve
        .create_point(
            &integer("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D"),
            &integer("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"),
        )
        .unwrap();
    let alice = party::<&FpCtCurve<'_>>(
        &g,
        "6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE",
        "83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563",
    );
    let bill = party::<&FpCtCurve<'_>>(
        &g,
        "5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53",
        "33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80",
    );
    known_answer(
        &alice,
        &bill,
        "55b0ac62a6b927ba23703832c853ded4",
        "284c8f198f141b502e81250f1581c7e9eeb4ca6990f9e02df388b45471f5bc5c",
        "23444daf8ed7534366cb901c84b3bdbb63504f4065c1116c91a4c00697e6cf7a",
    );
}

#[test]
fn the_f2m_test_curve_with_cofactor_four_matches_bouncy_castle() {
    let field = F2mField::trinomial(257, 12).unwrap();
    let curve = F2mCtCurve::new(
        field,
        &[0; 33],
        &bytes("00E78BCD09746C202378A7E72B12BCE00266B9627ECB0B5A25367AD1AD4CC6242B"),
        Some(integer(
            "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBC972CF7E6B6F900945B3C6A0CF6161D",
        )),
        Some(PaddedBigUint::from(4u8)),
    )
    .unwrap();
    let g = curve
        .create_point(
            &bytes("00CDB9CA7F1E6B0441F658343F4B10297C0EF9B6491082400A62E7A7485735FADD"),
            &bytes("013DE74DA65951C4D76DC89220D5F7777A611B1C38BAE260B175951DC8060C2B3E"),
        )
        .unwrap();
    let alice = party::<&F2mCtCurve>(
        &g,
        "4813903D254F2C20A94BC5704238496954BB5279F861952EF2C5298E84D2CEAA",
        "54A3D6673FF3A6BD6B02EBB164C2A3AF6D4A4906229D9BFCE68CC366A2E64BA4",
    );
    let bill = party::<&F2mCtCurve>(
        &g,
        "08F41BAE0922F47C212803FE681AD52B9BF28A35E1CD0EC273A2CF813E8FD1DC",
        "1F21933387BEF781D0A8F7FD708C5AE0A56EE3F423DBC2FE5BDF6F068C53F7AD",
    );
    known_answer(
        &alice,
        &bill,
        "8c2b03289aa7126555dc660cfc29fd74",
        "d8294c4c0f0ac180feac95e8a0d786638c9e915b9a684b2348809af03a0de2a5",
        "52089e706911b58fd5e7c7b2ab5cf32bb61e481ef1e114a1e33d99eec84b5a4f",
    );
}

#[test]
fn errors_are_reported() {
    let field = FpField::new(integer(
        "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",
    ))
    .unwrap();
    let curve = FpCtCurve::new(
        &field,
        &integer("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498"),
        &integer("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A"),
        Some(integer(
            "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",
        )),
        Some(PaddedBigUint::from(1u8)),
    )
    .unwrap();
    let g = curve
        .create_point(
            &integer("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D"),
            &integer("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"),
        )
        .unwrap();
    let alice = party::<&FpCtCurve<'_>>(&g, "0101", "0202");
    let bill = party::<&FpCtCurve<'_>>(&g, "0303", "0404");

    let uninitialized = Sm2KeyExchange::<&FpCtCurve<'_>>::new();
    assert_eq!(
        uninitialized.calculate_key(&public(&bill, BILL), &mut [0; 16]),
        Err(Sm2Error::NotInitialized)
    );

    let initiator = exchange(&alice, true, ALICE);
    assert_eq!(
        initiator.calculate_key_with_confirmation(None, &public(&bill, BILL), &mut [0; 16]),
        Err(Sm2Error::MissingConfirmationTag)
    );
    let mut key = [0xffu8; 16];
    assert_eq!(
        initiator.calculate_key_with_confirmation(Some(&[0; 32]), &public(&bill, BILL), &mut key),
        Err(Sm2Error::ConfirmationMismatch)
    );
    assert_eq!(key, [0; 16], "the key is wiped on a mismatch");

    let too_long = vec![0u8; 8192];
    let mut exchange = Sm2KeyExchange::new();
    assert_eq!(
        exchange.init(
            &Sm2KeyExchangePrivateParams::new(
                true,
                alice.static_private.clone(),
                alice.ephemeral_private.clone()
            )
            .with_user_id(too_long.clone())
        ),
        Err(Sm2Error::InvalidUserId)
    );
    assert_eq!(
        initiator.calculate_key(&public(&bill, &too_long), &mut [0; 16]),
        Err(Sm2Error::InvalidUserId)
    );
}
