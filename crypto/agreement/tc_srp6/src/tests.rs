//! RFC 5054 附錄 B 的向量，即 BC `Srp6Test.Rfc5054AppendixBTestVectors`。向量的 a 小於
//! `generate_private_value` 的下限，抽不出來，所以同 BC 覆寫 `SelectPrivateValue` 的作法，
//! 經由 crate 內的 `credentials_with` 直接給定 a 與 b；這個測試因此放在 crate 裡。

use crate::standard_groups::rfc5054_1024;
use crate::utilities::{calculate_k, calculate_u, calculate_x};
use crate::{Srp6Client, Srp6Server, Srp6VerifierGenerator};
use alloc::vec::Vec;
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_sha::Sha1Digest;

fn integer(hex: &str) -> PaddedBigUint {
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    PaddedBigUint::from_be(&bytes).unwrap()
}

/// 沒用到的亂數來源：向量直接給定私密值。
struct NoRng;

#[test]
fn the_rfc_5054_appendix_b_vectors_match() {
    let identity = b"alice";
    let password = b"password123";
    let salt = [
        0xbe, 0xb2, 0x53, 0x79, 0xd1, 0xa8, 0x58, 0x1e, 0xb5, 0xa7, 0x27, 0x67, 0x3a, 0x24, 0x41,
        0xee,
    ];
    let group = rfc5054_1024();
    let (n, g) = (group.n(), group.g());

    let a = integer("60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393");
    let b = integer("E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20");
    let expected_v = integer(
        "7E273DE8696FFC4F4E337D05B4B375BEB0DDE1569E8FA00A9886D812\
         9BADA1F1822223CA1A605B530E379BA4729FDC59F105B4787E5186F5\
         C671085A1447B52A48CF1970B4FB6F8400BBF4CEBFBB168152E08AB5\
         EA53D15C1AFF87B2B9DA6E04E058AD51CC72BFC9033B564E26480D78\
         E955A5E29E7AB245DB2BE315E2099AFB",
    );
    let expected_a = integer(
        "61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC4\
         4352E8903211C04692272D8B2D1A5358A2CF1B6E0BFCF99F921530EC\
         8E39356179EAE45E42BA92AEACED825171E1E8B9AF6D9C03E1327F44\
         BE087EF06530E69F66615261EEF54073CA11CF5858F0EDFDFE15EFEA\
         B349EF5D76988A3672FAC47B0769447B",
    );
    let expected_b = integer(
        "BD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011\
         BAF38964DC46A0670DD125B95A981652236F99D9B681CBF87837EC99\
         6C6DA04453728610D0C6DDB58B318885D7D82C7F8DEB75CE7BD4FBAA\
         37089E6F9C6059F388838E7A00030B331EB76840910440B1B27AAEAE\
         EB4012B7D7665238A8E3FB004B117B58",
    );
    let expected_s = integer(
        "B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D\
         233861E359B48220F7C4693C9AE12B0A6F67809F0876E2D013800D6C\
         41BB59B6D5979B5C00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F\
         3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212D\
         C346D7E474B29EDE8A469FFECA686E5A",
    );

    let k = calculate_k(&mut Sha1Digest::new(), n, g);
    assert_eq!(k, integer("7556AA045AEF2CDD07ABAF0F665C3E818913186F"), "k");
    let x = calculate_x(&mut Sha1Digest::new(), &salt, identity, password);
    assert_eq!(x, integer("94B7555AABE9127CC58CCF4993DB6CF84D16C124"), "x");

    let mut generator = Srp6VerifierGenerator::new(Sha1Digest::new());
    generator.init(&group).unwrap();
    let v = generator
        .generate_verifier(&salt, identity, password)
        .unwrap();
    assert_eq!(v, expected_v, "v");

    let mut client = Srp6Client::new(Sha1Digest::new(), NoRng);
    client.init(&group).unwrap();
    let public_a = client
        .credentials_with(&salt, identity, password, a)
        .unwrap();
    assert_eq!(public_a, expected_a, "A");

    let mut server = Srp6Server::new(Sha1Digest::new(), NoRng);
    server.init(&group, &v).unwrap();
    let public_b = server.credentials_with(b).unwrap();
    assert_eq!(public_b, expected_b, "B");

    let u = calculate_u(&mut Sha1Digest::new(), n, &public_a, &public_b);
    assert_eq!(u, integer("CE38B9593487DA98554ED47D70A7AE5F462EF019"), "u");

    assert_eq!(
        client.calculate_secret(&public_b).unwrap(),
        expected_s,
        "client S"
    );
    assert_eq!(
        server.calculate_secret(&public_a).unwrap(),
        expected_s,
        "server S"
    );
}
