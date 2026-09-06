include!("data/vectors.rs");
include!("data/public_keys.rs");

#[test]
fn bc_public_key_validation() {
    for &(full, expected, key) in PUBLIC_KEYS {
        let key = hex(key).try_into().unwrap();
        assert_eq!(
            if full {
                validate_public_key(&key)
            } else {
                validate_public_key_partial(&key)
            },
            expected
        );
    }
}
use tc_ed448::*;
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
#[test]
fn all_rfc8032_vectors() {
    for &(mode, sk, pk, m, ctx, sig, label) in VECTORS {
        let sk: [u8; 57] = hex(sk).try_into().unwrap();
        let pk: [u8; 57] = hex(pk).try_into().unwrap();
        let sig: [u8; 114] = hex(sig).try_into().unwrap();
        let m = hex(m);
        let ctx = hex(ctx);
        let ph = prehash(&m);
        assert_eq!(public_key(&sk), pk, "{label}");
        assert!(validate_public_key(&pk), "{label}");
        let actual = if mode == 0 {
            sign(&sk, &m, &ctx).unwrap()
        } else {
            sign_prehashed(&sk, &ph, &ctx).unwrap()
        };
        assert_eq!(actual, sig, "{label}");
        let check = |s: &[u8; 114]| {
            if mode == 0 {
                verify(&pk, &m, s, &ctx)
            } else {
                verify_prehashed(&pk, &ph, s, &ctx)
            }
        };
        assert!(check(&sig), "{label}");
        assert!(
            if mode == 0 {
                verify_strict(&pk, &m, &sig, &ctx)
            } else {
                verify_prehashed_strict(&pk, &ph, &sig, &ctx)
            },
            "strict {label}"
        );
        for byte in [0, 56, 57, 113] {
            let mut bad = sig;
            bad[byte] ^= 1;
            assert!(!check(&bad), "{label} corrupt {byte}");
        }
    }
}
#[test]
fn rejects_malleability_identity_noncanonical_and_wrong_domains() {
    let seed = [7; 57];
    let pk = public_key(&seed);
    let sig = sign(&seed, b"message", b"ctx").unwrap();
    assert!(!verify(&pk, b"other", &sig, b"ctx"));
    assert!(!verify(&pk, b"message", &sig, b""));
    let mut bad = sig;
    bad[57..].fill(255);
    assert!(!verify(&pk, b"message", &bad, b"ctx"));
    let mut identity = [0; 57];
    identity[0] = 1;
    assert!(!validate_public_key(&identity));
    identity[56] = 128;
    assert!(!validate_public_key(&identity));
    assert!(!validate_public_key(&[255; 57]));
    assert!(sign(&seed, b"", &[0; 256]).is_err());
    assert!(!verify(&pk, b"", &sig, &[0; 256]));
    let ctx = sign(&seed, b"message", &[1; 255]).unwrap();
    assert!(verify(&pk, b"message", &ctx, &[1; 255]));
}
