mod common;

use common::{GX, GY, SYSTEMS, bytes, generator, int, sect163r2, sect163r2_ct};
use tc_ec_core_v2::{Curve, FieldElement, Point, PointDecodeError, PointEncodeError};
use tc_f2m_curve_v2::{F2mCtCurve, F2mVarCurve};

fn uncompressed() -> Vec<u8> {
    bytes(&format!("04{GX}{GY}"))
}

// SEC 2 gives the compressed sect163r2 generator with the prefix 03.
fn compressed() -> Vec<u8> {
    bytes(&format!("03{GX}"))
}

#[test]
fn the_generator_encodes_as_sec_2_lists_it_in_every_coordinate_system() {
    for system in SYSTEMS {
        let curve = sect163r2(system);
        // 2G - G, so that the projective systems encode a scaled point.
        let g = generator(&curve).twice().add(&generator(&curve).negate());
        assert_eq!(g.encode(false), uncompressed(), "{system:?}");
        assert_eq!(g.encode(true), compressed(), "{system:?}");
        assert_eq!(curve.field_element_encoding_length(), 21);
        assert_eq!(curve.affine_point_encoding_length(true), 22);
    }
    let curve = sect163r2_ct();
    let g = curve.create_point(&bytes(GX), &bytes(GY)).unwrap();
    assert_eq!(g.encode(false), uncompressed());
    assert_eq!(g.encode(true), compressed());
}

#[test]
fn every_form_decodes_back_to_the_point_on_both_sets() {
    let ct = sect163r2_ct();
    for system in SYSTEMS {
        let var = sect163r2(system);
        let g = generator(&var);
        for k in 1..24 {
            let p = <&F2mVarCurve as Curve>::multiply(&g, &int(k));
            for encoded in [p.encode(false), p.encode(true)] {
                assert!(
                    var.decode_point(&encoded).unwrap() == p,
                    "{system:?}, k = {k}"
                );
                let q = ct.decode_point(&encoded).unwrap();
                assert!(q.x() == p.x() && q.y() == p.y(), "k = {k}");
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
    let curve = sect163r2(SYSTEMS[2]);
    assert_eq!(curve.infinity().encode(true), [0]);
    assert!(curve.decode_point(&[0]).unwrap().is_infinity());

    let handle = &curve;
    let root_b = Curve::b(&handle).sqrt().unwrap();
    let t = <&F2mVarCurve as Curve>::create_point(&handle, Curve::zero(&handle), root_b);
    let encoded = t.encode(true);
    assert_eq!(encoded[0], 0x02);
    assert!(curve.decode_point(&encoded).unwrap() == t);
    assert!(curve.decompress_point(0, &encoded[1..]).unwrap() == t);
}

#[test]
fn malformed_encodings_are_refused() {
    let curve = sect163r2(SYSTEMS[0]);
    let ct: F2mCtCurve = sect163r2_ct();
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
}

#[test]
fn encoding_into_a_short_buffer_writes_nothing() {
    let curve = sect163r2_ct();
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
