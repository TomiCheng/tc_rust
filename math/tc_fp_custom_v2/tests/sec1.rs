mod common;

use common::*;
use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::{Curve, PointDecodeError, PointEncodeError};
use tc_fp_curve_v2::{FpCtCurve, FpVarCurve};
use tc_fp_custom_v2::named_curves::*;
use tc_fp_custom_v2::*;

type Decoded = Result<Vec<u8>, PointDecodeError>;
type Multiply<'a> = &'a dyn Fn(&PaddedBigUint) -> [Vec<u8>; 4];
type Decode<'a> = &'a dyn Fn(&[u8]) -> [Decoded; 2];
type Decompress<'a> = &'a dyn Fn(u8, &[u8]) -> Option<Vec<u8>>;
type Create<'a> = &'a dyn Fn(&[u8], &[u8]) -> [Option<SecPError>; 2];

// The inherent methods of one curve's Ct and Var sets, which a generic helper cannot name
// outside the crate, as the element trait is sealed.
struct Custom<'a> {
    len: usize,
    // k·G from the Ct and the Var generator, compressed and not.
    multiply: Multiply<'a>,
    // The Ct and the Var decoding, encoded back uncompressed.
    decode: Decode<'a>,
    decompress: Decompress<'a>,
    create: Create<'a>,
}

fn hybrid(uncompressed: &[u8]) -> Vec<u8> {
    let mut bytes = uncompressed.to_vec();
    bytes[0] = 6 | (bytes[bytes.len() - 1] & 1);
    bytes
}

// Every form a point takes in SEC 1 is what the generic curves write, and decodes back to
// it on both sets; every malformed one is turned down with its reason.
fn check(params: &Params, custom: Custom<'_>, generic: impl Fn(&PaddedBigUint) -> [Vec<u8>; 2]) {
    let len = custom.len;
    let mut state = 0x5EC1;
    for _ in 0..4 {
        let k = scalar(&mut state, len);
        let [compressed, uncompressed] = generic(&k);
        let [ct_c, ct_u, var_c, var_u] = (custom.multiply)(&k);
        assert_eq!(
            [&ct_c, &ct_u, &var_c, &var_u],
            [&compressed, &uncompressed, &compressed, &uncompressed]
        );
        assert_eq!(compressed.len(), 1 + len);
        assert_eq!(uncompressed.len(), 1 + 2 * len);
        for bytes in [&compressed, &uncompressed, &hybrid(&uncompressed)] {
            let ok = Ok(uncompressed.clone());
            assert_eq!((custom.decode)(bytes), [ok.clone(), ok]);
        }
        let mut inconsistent = hybrid(&uncompressed);
        inconsistent[0] ^= 1;
        let error = Err(PointDecodeError::InconsistentHybridY);
        assert_eq!((custom.decode)(&inconsistent), [error.clone(), error]);
        let decompressed = (custom.decompress)(compressed[0] & 1, &compressed[1..]);
        assert_eq!(decompressed, Some(uncompressed));
    }
    assert_eq!((custom.decode)(&[0]), [Ok(vec![0]), Ok(vec![0])]);

    let refused = |bytes: &[u8], error: PointDecodeError| {
        assert_eq!((custom.decode)(bytes), [Err(error), Err(error)]);
    };
    let (p, gx, gy) = (hex(params.p), hex(params.gx), hex(params.gy));
    let compressed = |x: &[u8]| [&[2][..], x].concat();
    refused(&[], PointDecodeError::Empty);
    refused(&[0, 0], PointDecodeError::InvalidLength);
    refused(&compressed(&gx[1..]), PointDecodeError::InvalidLength);
    refused(&compressed(&p), PointDecodeError::CoordinateOutOfRange);
    refused(
        &[&[5][..], &gx].concat(),
        PointDecodeError::UnknownEncoding(5),
    );
    let mut off = [&[4][..], &gx, &gy].concat();
    off[2 * len] ^= 1;
    refused(&off, PointDecodeError::NotOnCurve);
    // About half of the x have no point; one of the first few does not.
    let missing = (0u8..64)
        .map(|i| {
            let mut x = vec![0; len];
            x[len - 1] = i;
            x
        })
        .find(|x| (custom.decompress)(0, x).is_none())
        .unwrap();
    refused(&compressed(&missing), PointDecodeError::NotOnCurve);

    let short = SecPError::InvalidLength {
        expected: len,
        actual: len - 1,
    };
    assert_eq!((custom.create)(&gx[1..], &gy), [Some(short), Some(short)]);
    let out_of_range = Some(SecPError::NotBelowModulus);
    assert_eq!((custom.create)(&gx, &p), [out_of_range, out_of_range]);
    assert_eq!((custom.create)(&gx, &gy), [None, None]);
}

#[test]
fn secp256r1_points_encode_and_decode_as_the_generic_curves_do() {
    let field = field(&P256);
    let generic = generic_ct(&field, &P256);
    let reference = generic.create_point(&int(P256.gx), &int(P256.gy)).unwrap();
    let (ct, var) = (SECP256R1.ct_curve(), SECP256R1.var_curve());
    let (g, h) = (SECP256R1.ct_generator(&ct), SECP256R1.var_generator(&var));
    let custom = Custom {
        len: ct.field_element_encoding_length(),
        multiply: &|k| {
            let (p, q) = (g.multiply(k), <&SecPVarCurve<_>>::multiply(&h, k));
            [
                p.encode(true),
                p.encode(false),
                q.encode(true),
                q.encode(false),
            ]
        },
        decode: &|bytes| {
            [
                ct.decode_point(bytes).map(|p| p.encode(false)),
                var.decode_point(bytes).map(|p| p.encode(false)),
            ]
        },
        decompress: &|y_tilde, x| var.decompress_point(y_tilde, x).map(|p| p.encode(false)),
        create: &|x, y| [ct.create_point(x, y).err(), var.create_point(x, y).err()],
    };
    check(&P256, custom, |k| {
        let p = <&FpCtCurve>::multiply(&reference, k);
        [p.encode(true), p.encode(false)]
    });
}

#[test]
fn secp256k1_points_encode_and_decode_as_the_generic_curves_do() {
    let field = field(&K256);
    let generic = generic_var(&field, &K256);
    let reference = generic.create_point(&int(K256.gx), &int(K256.gy)).unwrap();
    let (ct, var) = (SECP256K1.ct_curve(), SECP256K1.var_curve());
    let (g, h) = (SECP256K1.ct_generator(&ct), SECP256K1.var_generator(&var));
    let custom = Custom {
        len: ct.field_element_encoding_length(),
        multiply: &|k| {
            let (p, q) = (g.multiply(k), <&SecPVarCurve<_>>::multiply(&h, k));
            [
                p.encode(true),
                p.encode(false),
                q.encode(true),
                q.encode(false),
            ]
        },
        decode: &|bytes| {
            [
                ct.decode_point(bytes).map(|p| p.encode(false)),
                var.decode_point(bytes).map(|p| p.encode(false)),
            ]
        },
        decompress: &|y_tilde, x| var.decompress_point(y_tilde, x).map(|p| p.encode(false)),
        create: &|x, y| [ct.create_point(x, y).err(), var.create_point(x, y).err()],
    };
    check(&K256, custom, |k| {
        let p = <&FpVarCurve>::multiply(&reference, k);
        [p.encode(true), p.encode(false)]
    });
}

#[test]
fn secp384r1_points_encode_and_decode_as_the_generic_curves_do() {
    let field = field(&P384);
    let generic = generic_var(&field, &P384);
    let reference = generic.create_point(&int(P384.gx), &int(P384.gy)).unwrap();
    let (ct, var) = (SECP384R1.ct_curve(), SECP384R1.var_curve());
    let (g, h) = (SECP384R1.ct_generator(&ct), SECP384R1.var_generator(&var));
    let custom = Custom {
        len: ct.field_element_encoding_length(),
        multiply: &|k| {
            let (p, q) = (g.multiply(k), <&SecPVarCurve<_>>::multiply(&h, k));
            [
                p.encode(true),
                p.encode(false),
                q.encode(true),
                q.encode(false),
            ]
        },
        decode: &|bytes| {
            [
                ct.decode_point(bytes).map(|p| p.encode(false)),
                var.decode_point(bytes).map(|p| p.encode(false)),
            ]
        },
        decompress: &|y_tilde, x| var.decompress_point(y_tilde, x).map(|p| p.encode(false)),
        create: &|x, y| [ct.create_point(x, y).err(), var.create_point(x, y).err()],
    };
    check(&P384, custom, |k| {
        let p = <&FpVarCurve>::multiply(&reference, k);
        [p.encode(true), p.encode(false)]
    });
}

#[test]
fn a_short_buffer_is_turned_down_and_left_alone() {
    let curve = SECP256R1.ct_curve();
    let g = SECP256R1.ct_generator(&curve);
    let mut short = [0xAA; 32];
    assert_eq!(
        g.encode_to(true, &mut short),
        Err(PointEncodeError::OutputTooShort {
            required: 33,
            available: 32,
        })
    );
    assert_eq!(short, [0xAA; 32]);
    assert_eq!(curve.infinity().encode(true), [0]);
    assert_eq!(curve.affine_point_encoding_length(false), 65);
}

#[cfg(feature = "small-curves")]
#[test]
fn secp128r1_points_encode_and_decode_as_the_generic_curves_do() {
    let field = field(&R128);
    let generic = generic_var(&field, &R128);
    let reference = generic.create_point(&int(R128.gx), &int(R128.gy)).unwrap();
    let (ct, var) = (SECP128R1.ct_curve(), SECP128R1.var_curve());
    let (g, h) = (SECP128R1.ct_generator(&ct), SECP128R1.var_generator(&var));
    let custom = Custom {
        len: ct.field_element_encoding_length(),
        multiply: &|k| {
            let (p, q) = (g.multiply(k), <&SecPVarCurve<_>>::multiply(&h, k));
            [
                p.encode(true),
                p.encode(false),
                q.encode(true),
                q.encode(false),
            ]
        },
        decode: &|bytes| {
            [
                ct.decode_point(bytes).map(|p| p.encode(false)),
                var.decode_point(bytes).map(|p| p.encode(false)),
            ]
        },
        decompress: &|y_tilde, x| var.decompress_point(y_tilde, x).map(|p| p.encode(false)),
        create: &|x, y| [ct.create_point(x, y).err(), var.create_point(x, y).err()],
    };
    check(&R128, custom, |k| {
        let p = <&FpVarCurve>::multiply(&reference, k);
        [p.encode(true), p.encode(false)]
    });
}

#[cfg(feature = "small-curves")]
#[test]
fn secp160k1_points_encode_and_decode_as_the_generic_curves_do() {
    let field = field(&K160);
    let generic = generic_var(&field, &K160);
    let reference = generic.create_point(&int(K160.gx), &int(K160.gy)).unwrap();
    let (ct, var) = (SECP160K1.ct_curve(), SECP160K1.var_curve());
    let (g, h) = (SECP160K1.ct_generator(&ct), SECP160K1.var_generator(&var));
    let custom = Custom {
        len: ct.field_element_encoding_length(),
        multiply: &|k| {
            let (p, q) = (g.multiply(k), <&SecPVarCurve<_>>::multiply(&h, k));
            [
                p.encode(true),
                p.encode(false),
                q.encode(true),
                q.encode(false),
            ]
        },
        decode: &|bytes| {
            [
                ct.decode_point(bytes).map(|p| p.encode(false)),
                var.decode_point(bytes).map(|p| p.encode(false)),
            ]
        },
        decompress: &|y_tilde, x| var.decompress_point(y_tilde, x).map(|p| p.encode(false)),
        create: &|x, y| [ct.create_point(x, y).err(), var.create_point(x, y).err()],
    };
    check(&K160, custom, |k| {
        let p = <&FpVarCurve>::multiply(&reference, k);
        [p.encode(true), p.encode(false)]
    });
}

#[cfg(feature = "small-curves")]
#[test]
fn secp160r1_points_encode_and_decode_as_the_generic_curves_do() {
    let field = field(&R160);
    let generic = generic_var(&field, &R160);
    let reference = generic.create_point(&int(R160.gx), &int(R160.gy)).unwrap();
    let (ct, var) = (SECP160R1.ct_curve(), SECP160R1.var_curve());
    let (g, h) = (SECP160R1.ct_generator(&ct), SECP160R1.var_generator(&var));
    let custom = Custom {
        len: ct.field_element_encoding_length(),
        multiply: &|k| {
            let (p, q) = (g.multiply(k), <&SecPVarCurve<_>>::multiply(&h, k));
            [
                p.encode(true),
                p.encode(false),
                q.encode(true),
                q.encode(false),
            ]
        },
        decode: &|bytes| {
            [
                ct.decode_point(bytes).map(|p| p.encode(false)),
                var.decode_point(bytes).map(|p| p.encode(false)),
            ]
        },
        decompress: &|y_tilde, x| var.decompress_point(y_tilde, x).map(|p| p.encode(false)),
        create: &|x, y| [ct.create_point(x, y).err(), var.create_point(x, y).err()],
    };
    check(&R160, custom, |k| {
        let p = <&FpVarCurve>::multiply(&reference, k);
        [p.encode(true), p.encode(false)]
    });
}

#[cfg(feature = "small-curves")]
#[test]
fn secp160r2_points_encode_and_decode_as_the_generic_curves_do() {
    let field = field(&R160_2);
    let generic = generic_var(&field, &R160_2);
    let reference = generic
        .create_point(&int(R160_2.gx), &int(R160_2.gy))
        .unwrap();
    let (ct, var) = (SECP160R2.ct_curve(), SECP160R2.var_curve());
    let (g, h) = (SECP160R2.ct_generator(&ct), SECP160R2.var_generator(&var));
    let custom = Custom {
        len: ct.field_element_encoding_length(),
        multiply: &|k| {
            let (p, q) = (g.multiply(k), <&SecPVarCurve<_>>::multiply(&h, k));
            [
                p.encode(true),
                p.encode(false),
                q.encode(true),
                q.encode(false),
            ]
        },
        decode: &|bytes| {
            [
                ct.decode_point(bytes).map(|p| p.encode(false)),
                var.decode_point(bytes).map(|p| p.encode(false)),
            ]
        },
        decompress: &|y_tilde, x| var.decompress_point(y_tilde, x).map(|p| p.encode(false)),
        create: &|x, y| [ct.create_point(x, y).err(), var.create_point(x, y).err()],
    };
    check(&R160_2, custom, |k| {
        let p = <&FpVarCurve>::multiply(&reference, k);
        [p.encode(true), p.encode(false)]
    });
}

#[test]
fn secp192k1_points_encode_and_decode_as_the_generic_curves_do() {
    let field = field(&K192);
    let generic = generic_var(&field, &K192);
    let reference = generic.create_point(&int(K192.gx), &int(K192.gy)).unwrap();
    let (ct, var) = (SECP192K1.ct_curve(), SECP192K1.var_curve());
    let (g, h) = (SECP192K1.ct_generator(&ct), SECP192K1.var_generator(&var));
    let custom = Custom {
        len: ct.field_element_encoding_length(),
        multiply: &|k| {
            let (p, q) = (g.multiply(k), <&SecPVarCurve<_>>::multiply(&h, k));
            [
                p.encode(true),
                p.encode(false),
                q.encode(true),
                q.encode(false),
            ]
        },
        decode: &|bytes| {
            [
                ct.decode_point(bytes).map(|p| p.encode(false)),
                var.decode_point(bytes).map(|p| p.encode(false)),
            ]
        },
        decompress: &|y_tilde, x| var.decompress_point(y_tilde, x).map(|p| p.encode(false)),
        create: &|x, y| [ct.create_point(x, y).err(), var.create_point(x, y).err()],
    };
    check(&K192, custom, |k| {
        let p = <&FpVarCurve>::multiply(&reference, k);
        [p.encode(true), p.encode(false)]
    });
}

#[test]
fn secp192r1_points_encode_and_decode_as_the_generic_curves_do() {
    let field = field(&P192);
    let generic = generic_var(&field, &P192);
    let reference = generic.create_point(&int(P192.gx), &int(P192.gy)).unwrap();
    let (ct, var) = (SECP192R1.ct_curve(), SECP192R1.var_curve());
    let (g, h) = (SECP192R1.ct_generator(&ct), SECP192R1.var_generator(&var));
    let custom = Custom {
        len: ct.field_element_encoding_length(),
        multiply: &|k| {
            let (p, q) = (g.multiply(k), <&SecPVarCurve<_>>::multiply(&h, k));
            [
                p.encode(true),
                p.encode(false),
                q.encode(true),
                q.encode(false),
            ]
        },
        decode: &|bytes| {
            [
                ct.decode_point(bytes).map(|p| p.encode(false)),
                var.decode_point(bytes).map(|p| p.encode(false)),
            ]
        },
        decompress: &|y_tilde, x| var.decompress_point(y_tilde, x).map(|p| p.encode(false)),
        create: &|x, y| [ct.create_point(x, y).err(), var.create_point(x, y).err()],
    };
    check(&P192, custom, |k| {
        let p = <&FpVarCurve>::multiply(&reference, k);
        [p.encode(true), p.encode(false)]
    });
}

#[test]
fn secp224k1_points_encode_and_decode_as_the_generic_curves_do() {
    let field = field(&K224);
    let generic = generic_var(&field, &K224);
    let reference = generic.create_point(&int(K224.gx), &int(K224.gy)).unwrap();
    let (ct, var) = (SECP224K1.ct_curve(), SECP224K1.var_curve());
    let (g, h) = (SECP224K1.ct_generator(&ct), SECP224K1.var_generator(&var));
    let custom = Custom {
        len: ct.field_element_encoding_length(),
        multiply: &|k| {
            let (p, q) = (g.multiply(k), <&SecPVarCurve<_>>::multiply(&h, k));
            [
                p.encode(true),
                p.encode(false),
                q.encode(true),
                q.encode(false),
            ]
        },
        decode: &|bytes| {
            [
                ct.decode_point(bytes).map(|p| p.encode(false)),
                var.decode_point(bytes).map(|p| p.encode(false)),
            ]
        },
        decompress: &|y_tilde, x| var.decompress_point(y_tilde, x).map(|p| p.encode(false)),
        create: &|x, y| [ct.create_point(x, y).err(), var.create_point(x, y).err()],
    };
    check(&K224, custom, |k| {
        let p = <&FpVarCurve>::multiply(&reference, k);
        [p.encode(true), p.encode(false)]
    });
}

#[test]
fn secp224r1_points_encode_and_decode_as_the_generic_curves_do() {
    let field = field(&P224);
    let generic = generic_var(&field, &P224);
    let reference = generic.create_point(&int(P224.gx), &int(P224.gy)).unwrap();
    let (ct, var) = (SECP224R1.ct_curve(), SECP224R1.var_curve());
    let (g, h) = (SECP224R1.ct_generator(&ct), SECP224R1.var_generator(&var));
    let custom = Custom {
        len: ct.field_element_encoding_length(),
        multiply: &|k| {
            let (p, q) = (g.multiply(k), <&SecPVarCurve<_>>::multiply(&h, k));
            [
                p.encode(true),
                p.encode(false),
                q.encode(true),
                q.encode(false),
            ]
        },
        decode: &|bytes| {
            [
                ct.decode_point(bytes).map(|p| p.encode(false)),
                var.decode_point(bytes).map(|p| p.encode(false)),
            ]
        },
        decompress: &|y_tilde, x| var.decompress_point(y_tilde, x).map(|p| p.encode(false)),
        create: &|x, y| [ct.create_point(x, y).err(), var.create_point(x, y).err()],
    };
    check(&P224, custom, |k| {
        let p = <&FpVarCurve>::multiply(&reference, k);
        [p.encode(true), p.encode(false)]
    });
}

#[test]
fn secp521r1_points_encode_and_decode_as_the_generic_curves_do() {
    let field = field(&P521);
    let generic = generic_var(&field, &P521);
    let reference = generic.create_point(&int(P521.gx), &int(P521.gy)).unwrap();
    let (ct, var) = (SECP521R1.ct_curve(), SECP521R1.var_curve());
    let (g, h) = (SECP521R1.ct_generator(&ct), SECP521R1.var_generator(&var));
    let custom = Custom {
        len: ct.field_element_encoding_length(),
        multiply: &|k| {
            let (p, q) = (g.multiply(k), <&SecPVarCurve<_>>::multiply(&h, k));
            [
                p.encode(true),
                p.encode(false),
                q.encode(true),
                q.encode(false),
            ]
        },
        decode: &|bytes| {
            [
                ct.decode_point(bytes).map(|p| p.encode(false)),
                var.decode_point(bytes).map(|p| p.encode(false)),
            ]
        },
        decompress: &|y_tilde, x| var.decompress_point(y_tilde, x).map(|p| p.encode(false)),
        create: &|x, y| [ct.create_point(x, y).err(), var.create_point(x, y).err()],
    };
    check(&P521, custom, |k| {
        let p = <&FpVarCurve>::multiply(&reference, k);
        [p.encode(true), p.encode(false)]
    });
}

#[test]
fn sm2p256v1_points_encode_and_decode_as_the_generic_curves_do() {
    let field = field(&SM2);
    let generic = generic_var(&field, &SM2);
    let reference = generic.create_point(&int(SM2.gx), &int(SM2.gy)).unwrap();
    let (ct, var) = (SM2P256V1.ct_curve(), SM2P256V1.var_curve());
    let (g, h) = (SM2P256V1.ct_generator(&ct), SM2P256V1.var_generator(&var));
    let custom = Custom {
        len: ct.field_element_encoding_length(),
        multiply: &|k| {
            let (p, q) = (g.multiply(k), <&SecPVarCurve<_>>::multiply(&h, k));
            [
                p.encode(true),
                p.encode(false),
                q.encode(true),
                q.encode(false),
            ]
        },
        decode: &|bytes| {
            [
                ct.decode_point(bytes).map(|p| p.encode(false)),
                var.decode_point(bytes).map(|p| p.encode(false)),
            ]
        },
        decompress: &|y_tilde, x| var.decompress_point(y_tilde, x).map(|p| p.encode(false)),
        create: &|x, y| [ct.create_point(x, y).err(), var.create_point(x, y).err()],
    };
    check(&SM2, custom, |k| {
        let p = <&FpVarCurve>::multiply(&reference, k);
        [p.encode(true), p.encode(false)]
    });
}
