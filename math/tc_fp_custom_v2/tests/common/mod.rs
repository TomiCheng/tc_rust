#![allow(dead_code)]

use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_core_v2::{FieldElement, Point};
use tc_fp_curve_v2::{FpCtCurve, FpField, FpVarCurve};

/// A curve's parameters for the generic curves of `tc_fp_curve_v2`, with k·G for a fixed k,
/// computed apart by affine double-and-add over Python integers.
pub struct Params {
    pub p: &'static str,
    pub a: &'static str,
    pub b: &'static str,
    pub n: &'static str,
    pub gx: &'static str,
    pub gy: &'static str,
    pub k: &'static str,
    pub kg: &'static str,
}

pub const P256: Params = Params {
    p: "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    a: "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
    b: "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    n: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    gx: "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    gy: "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    k: "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186",
    kg: "049ed4fbadf89bb1cd3cbdd03737c6b55eb21667ef44baba27dca0daaa8527f1c03c52e145bc96ba39bc898fd2bc041afde2fb6c995555554cc3a4e2f2cafe58fc",
};

pub const K256: Params = Params {
    p: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
    a: "0000000000000000000000000000000000000000000000000000000000000000",
    b: "0000000000000000000000000000000000000000000000000000000000000007",
    n: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    gx: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    gy: "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
    k: "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186",
    kg: "04a5aa526ef6ce4fed9ad47ef2c9dece9610660689df07a192e3f641da734e6d8a170b53af42f0eb1f01f53c4237f5d318d030c0d27ae61d44f3089d3c0a3e60bf",
};

pub const P384: Params = Params {
    p: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
    a: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc",
    b: "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
    n: "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
    gx: "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
    gy: "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
    k: "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186abd0f51a3f6489aed3f81d42678cb1d6",
    kg: "04636e9f9fac4f6bff1e24a08aa64dbbfebffb0688d551e37b79bac8a6c057c9e02840d42b592439c9caf8279725b4e474498a6a9bacfd67bc78b4917088a0e49a63beb5735823a0a2cb676e05aefae20e1bc569c32258c93704d170d7f2e0c97d",
};

pub const R128: Params = Params {
    p: "fffffffdffffffffffffffffffffffff",
    a: "fffffffdfffffffffffffffffffffffc",
    b: "e87579c11079f43dd824993c2cee5ed3",
    n: "fffffffe0000000075a30d1b9038a115",
    gx: "161ff7528b899b2d0c28607ca52c5b86",
    gy: "cf5ac8395bafeb13c02da292dded7a83",
    k: "0b30557a9fc4e90e33587da2c7ec1136",
    kg: "04309538b00e4d727a1ad34445700241b03dd917d30f73ee1418c6ac7cf62b17b1",
};

pub const K160: Params = Params {
    p: "fffffffffffffffffffffffffffffffeffffac73",
    a: "0000000000000000000000000000000000000000",
    b: "0000000000000000000000000000000000000007",
    n: "0100000000000000000001b8fa16dfab9aca16b6b3",
    gx: "3b4c382ce37aa192a4019e763036f4f5dd4d7ebb",
    gy: "938cf935318fdced6bc28286531733c3f03c4fee",
    k: "0b30557a9fc4e90e33587da2c7ec11365b80a5ca",
    kg: "04f0d5f09692da765e47248e6f8c47d3f3eb40226720a604575313ab1a0ca6813613bd4b1e471e3338",
};

pub const R160: Params = Params {
    p: "ffffffffffffffffffffffffffffffff7fffffff",
    a: "ffffffffffffffffffffffffffffffff7ffffffc",
    b: "1c97befc54bd7a8b65acf89f81d4d4adc565fa45",
    n: "0100000000000000000001f4c8f927aed3ca752257",
    gx: "4a96b5688ef573284664698968c38bb913cbfc82",
    gy: "23a628553168947d59dcc912042351377ac5fb32",
    k: "0b30557a9fc4e90e33587da2c7ec11365b80a5ca",
    kg: "0404abb4fd678e579cd03ca348242e5242031490539223891eb6bebbbdaf040b6446fe99eb8e52d232",
};

pub const R160_2: Params = Params {
    p: "fffffffffffffffffffffffffffffffeffffac73",
    a: "fffffffffffffffffffffffffffffffeffffac70",
    b: "b4e134d3fb59eb8bab57274904664d5af50388ba",
    n: "0100000000000000000000351ee786a818f3a1a16b",
    gx: "52dcb034293a117e1f4ff11b30f7199d3144ce6d",
    gy: "feaffef2e331f296e071fa0df9982cfea7d43f2e",
    k: "0b30557a9fc4e90e33587da2c7ec11365b80a5ca",
    kg: "0436f953a0bd9fac4ce76653abe6f06bc3030ed5ee0174f0eea14b6a9306540a55c6b6a0bc4f5aa760",
};

pub const K192: Params = Params {
    p: "fffffffffffffffffffffffffffffffffffffffeffffee37",
    a: "000000000000000000000000000000000000000000000000",
    b: "000000000000000000000000000000000000000000000003",
    n: "fffffffffffffffffffffffe26f2fc170f69466a74defd8d",
    gx: "db4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d",
    gy: "9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d",
    k: "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e",
    kg: "041a36e8eb6983a4e959535dac0447bae32ca2ff95fb1e03d3b034b6acdb78b5984073444750506011e7cab77e2423d654",
};

pub const P192: Params = Params {
    p: "fffffffffffffffffffffffffffffffeffffffffffffffff",
    a: "fffffffffffffffffffffffffffffffefffffffffffffffc",
    b: "64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",
    n: "ffffffffffffffffffffffff99def836146bc9b1b4d22831",
    gx: "188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
    gy: "07192b95ffc8da78631011ed6b24cdd573f977a11e794811",
    k: "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e",
    kg: "04d4b1fab7cbeece42a76634bcddfd30da9e91b55c0e902d2e5f3ba8b5e408019275f8c4f105d766c71a1de3c52f2a61e0",
};

pub const K224: Params = Params {
    p: "fffffffffffffffffffffffffffffffffffffffffffffffeffffe56d",
    a: "00000000000000000000000000000000000000000000000000000000",
    b: "00000000000000000000000000000000000000000000000000000005",
    n: "010000000000000000000000000001dce8d2ec6184caf0a971769fb1f7",
    gx: "a1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c",
    gy: "7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5",
    k: "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2",
    kg: "045eb6f420c77dc97e4a307e1fb4c4128313542f55696124431e6431229bea82152fbe59080773f6b66198bf654167533e167153acb67d84fb",
};

pub const P224: Params = Params {
    p: "ffffffffffffffffffffffffffffffff000000000000000000000001",
    a: "fffffffffffffffffffffffffffffffefffffffffffffffffffffffe",
    b: "b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
    n: "ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d",
    gx: "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
    gy: "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34",
    k: "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2",
    kg: "04ed04e3c5d78afe25c312a678825e9b127c8e3b5d8fc3dd845a286cbb98acd4554d2bc55fa879df693f02aea7e41603c12931f52d3478c957",
};

pub const P521: Params = Params {
    p: "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    a: "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc",
    b: "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
    n: "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
    gx: "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
    gy: "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
    k: "0130557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186abed5d7999d1cdc0e3de9e46611fdea6be0f1add9f1a29f0bcdec46424432b0c5743",
    kg: "0401f5f8122798dd428b7f3516d81c129538255036fbee7c4bce54c2c6a793b855b917e363d9a6c3d2bc606f8ce6bbdc5e20341758b67aadda1538b651d7919e8201040069bd447594b9ac275ec6e2f3385aa3c787cc4b6583e1f4788ed26cbffddce00a89ebed085fe637b89c5a8f1c485137734977bf140f3c6b02611e43d2e95f02b21d",
};

pub const SM2: Params = Params {
    p: "fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff",
    a: "fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc",
    b: "28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93",
    n: "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123",
    gx: "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
    gy: "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
    k: "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186",
    kg: "041c2036352cfaa8dc4463e084551e7507fce8a90f1dfce99bda29653324e8fd94abbbf5bab4d5200044c3f69930886749a9ac1e5b24a5b37fd958eff0fb1c611e",
};

pub fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

pub fn int(text: &str) -> PaddedBigUint {
    let Ok(value) = <PaddedBigUint as ArrayEncoding<u8>>::from_be(&hex(text));
    value
}

pub fn field(params: &Params) -> FpField {
    FpField::new(int(params.p)).unwrap()
}

pub fn generic_ct<'a>(field: &'a FpField, params: &Params) -> FpCtCurve<'a> {
    let one = Some(PaddedBigUint::from(1u8));
    FpCtCurve::new(
        field,
        &int(params.a),
        &int(params.b),
        Some(int(params.n)),
        one,
    )
    .unwrap()
}

pub fn generic_var<'a>(field: &'a FpField, params: &Params) -> FpVarCurve<'a> {
    let one = Some(PaddedBigUint::from(1u8));
    FpVarCurve::new(
        field,
        &int(params.a),
        &int(params.b),
        Some(int(params.n)),
        one,
    )
    .unwrap()
}

pub fn encode<F: FieldElement>(x: Option<F>) -> Option<Vec<u8>> {
    x.map(|x| {
        let mut bytes = vec![0; x.encoded_length()];
        x.encode_to(&mut bytes);
        bytes
    })
}

/// `04 ‖ x ‖ y`, or `00` at infinity, through the affine coordinates of the `Point` trait.
pub fn uncompressed<P: Point>(p: &P) -> Vec<u8> {
    match (encode(p.x()), encode(p.y())) {
        (Some(x), Some(y)) => [&[4][..], &x, &y].concat(),
        _ => vec![0],
    }
}

/// The same affine point, whatever the two curves' types.
pub fn same<P: Point, Q: Point>(p: &P, q: &Q) {
    assert_eq!(uncompressed(p), uncompressed(q));
}

/// xorshift64, for scalars that differ loop to loop but not run to run.
pub fn scalar(state: &mut u64, len: usize) -> PaddedBigUint {
    let bytes: Vec<u8> = (0..len)
        .map(|_| {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *state as u8
        })
        .collect();
    let Ok(k) = <PaddedBigUint as ArrayEncoding<u8>>::from_be(&bytes);
    k
}
