use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::{Curve, FieldElement, Point, PointDecodeError, PointEncodeError};
use tc_f2m_curve_v2::named_curves as generic;
use tc_f2m_custom_v2::named_curves::{SECT163K1, SECT163R1, SECT163R2};
use tc_f2m_custom_v2::{SecT163FieldElement, SecTError, SecTVarCurve};

const GX: &str = "03f0eba16286a2d57ea0991168d4994637e8343e36";
const GY: &str = "00d51fbc6c71a0094fa2cdd545b11c5c0c797324f1";

type Var<'a> = &'a SecTVarCurve<SecT163FieldElement>;

fn bytes(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn uncompressed() -> Vec<u8> {
    bytes(&format!("04{GX}{GY}"))
}

// SEC 2 gives the compressed sect163r2 generator with the prefix 03.
fn compressed() -> Vec<u8> {
    bytes(&format!("03{GX}"))
}

#[test]
fn the_generator_encodes_as_sec_2_lists_it_on_both_sets() {
    let var = SECT163R2.var_curve();
    // 2G - G, so that the projective point encodes a scaled point.
    let g = SECT163R2.var_generator(&var);
    let g = g.twice().add(&g.negate());
    assert_eq!(g.encode(false), uncompressed());
    assert_eq!(g.encode(true), compressed());
    assert_eq!(var.field_element_encoding_length(), 21);
    assert_eq!(var.affine_point_encoding_length(true), 22);

    let ct = SECT163R2.ct_curve();
    let g = ct.create_point(&bytes(GX), &bytes(GY)).unwrap();
    assert_eq!(g.encode(false), uncompressed());
    assert_eq!(g.encode(true), compressed());
}

// Same point, same bytes: the specialized encoding is the generic curve's, and each side
// decodes what the other wrote.
#[test]
fn encodings_match_the_generic_curves_and_decode_back() {
    for (custom, generic) in [
        (SECT163K1, generic::SECT163K1),
        (SECT163R1, generic::SECT163R1),
        (SECT163R2, generic::SECT163R2),
    ] {
        let (var, ct) = (custom.var_curve(), custom.ct_curve());
        let g = custom.var_generator(&var);
        let reference = generic.var_curve();
        let h = generic.var_generator(&reference);
        for k in 1..24u8 {
            let k = PaddedBigUint::from(k);
            let p = Var::multiply(&g, &k);
            let q = <&tc_f2m_curve_v2::F2mVarCurve>::multiply(&h, &k);
            for compressed in [false, true] {
                let encoded = p.encode(compressed);
                assert_eq!(encoded, q.encode(compressed));
                assert!(var.decode_point(&encoded).unwrap() == p);
                let r = ct.decode_point(&encoded).unwrap();
                assert!(r.x() == p.x() && r.y() == p.y());
                assert_eq!(r.encode(compressed), encoded);
            }
            let mut hybrid = p.encode(false);
            hybrid[0] = 0x06 | (p.encode(true)[0] & 1);
            assert!(var.decode_point(&hybrid).unwrap() == p);
            hybrid[0] ^= 1;
            assert_eq!(
                var.decode_point(&hybrid).unwrap_err(),
                PointDecodeError::InconsistentHybridY
            );
        }
    }
}

#[test]
fn infinity_and_the_point_of_order_two_round_trip() {
    let curve = SECT163R2.var_curve();
    assert_eq!(curve.infinity().encode(true), [0]);
    assert!(curve.decode_point(&[0]).unwrap().is_infinity());

    let handle = &curve;
    let root_b = Curve::b(&handle).sqrt().unwrap();
    let t = <Var<'_> as Curve>::create_point(&handle, Curve::zero(&handle), root_b);
    let encoded = t.encode(true);
    assert_eq!(encoded[0], 0x02);
    assert!(curve.decode_point(&encoded).unwrap() == t);
    assert!(curve.decompress_point(0, &encoded[1..]).unwrap() == t);
}

#[test]
fn malformed_encodings_are_refused() {
    let curve = SECT163R2.var_curve();
    let ct = SECT163R2.ct_curve();
    let refuse = |encoded: &[u8], error| {
        assert_eq!(curve.decode_point(encoded).unwrap_err(), error);
        assert_eq!(ct.decode_point(encoded).unwrap_err(), error);
    };
    refuse(&[], PointDecodeError::Empty);
    refuse(&[0, 0], PointDecodeError::InvalidLength);
    refuse(&compressed()[..21], PointDecodeError::InvalidLength);
    refuse(&uncompressed()[..42], PointDecodeError::InvalidLength);
    let mut wrong_tag = compressed();
    wrong_tag[0] = 0x05;
    refuse(&wrong_tag, PointDecodeError::UnknownEncoding(0x05));

    let mut too_high = compressed();
    too_high[1] = 0x08;
    refuse(&too_high, PointDecodeError::CoordinateOutOfRange);

    let mut off_curve = uncompressed();
    *off_curve.last_mut().unwrap() ^= 1;
    refuse(&off_curve, PointDecodeError::NotOnCurve);

    // Half of all x have no point; one turns up among the first few.
    let no_point = (1u8..=40)
        .map(|last| {
            let mut x = vec![0; 21];
            x[20] = last;
            x
        })
        .find(|x| curve.decompress_point(0, x).is_none())
        .expect("some x has no point");
    let mut encoded = vec![0x02];
    encoded.extend_from_slice(&no_point);
    refuse(&encoded, PointDecodeError::NotOnCurve);
    assert!(curve.decompress_point(2, &no_point).is_none());

    assert_eq!(
        ct.create_point(&bytes(GX)[1..], &bytes(GY)).unwrap_err(),
        SecTError::InvalidLength {
            expected: 21,
            actual: 20
        }
    );
    assert_eq!(
        ct.create_point(&too_high[1..], &bytes(GY)).unwrap_err(),
        SecTError::NotReduced
    );
}

#[test]
fn encoding_into_a_short_buffer_writes_nothing() {
    let curve = SECT163R2.ct_curve();
    let g = curve.create_point(&bytes(GX), &bytes(GY)).unwrap();
    let mut output = [0xAA; 21];
    assert_eq!(
        g.encode_to(true, &mut output),
        Err(PointEncodeError::OutputTooShort {
            required: 22,
            available: 21
        })
    );
    assert!(output.iter().all(|&byte| byte == 0xAA));
    let mut output = [0; 30];
    assert_eq!(g.encode_to(true, &mut output), Ok(22));
    assert_eq!(output[..22], compressed());
}
