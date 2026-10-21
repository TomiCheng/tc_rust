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
