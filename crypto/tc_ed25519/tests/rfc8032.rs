include!("data/vectors.rs");
include!("data/taming.rs");
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
use tc_ed25519::*;
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn bouncy_castle_taming_eddsa_verification_policy() {
    for &(number, expected, message, pk, signature) in TAMING {
        if signature.len() != 128 {
            assert!(!expected);
            continue;
        }
        let pk: [u8; 32] = hex(pk).try_into().unwrap();
        let m = hex(message);
        let bytes = hex(signature);
        let actual = bytes.try_into().is_ok_and(|sig| verify(&pk, &m, &sig));
        assert_eq!(actual, expected, "Taming #{number}");
        if number == 2 || number == 3 {
            let sig = hex(signature).try_into().unwrap();
            assert!(!verify_strict(&pk, &m, &sig));
        }
    }
}
#[test]
fn all_rfc8032_vectors() {
    for &(mode, sk, pk, m, ctx, sig, label) in VECTORS {
        let sk: [u8; 32] = hex(sk).try_into().unwrap();
        let pk: [u8; 32] = hex(pk).try_into().unwrap();
        let sig: [u8; 64] = hex(sig).try_into().unwrap();
        let m = hex(m);
        let ctx = hex(ctx);
        let ph = prehash(&m);
        assert_eq!(public_key(&sk), pk, "{label}");
        assert!(validate_public_key(&pk), "{label}");
        let actual = match mode {
            0 => sign(&sk, &m),
            1 => sign_ctx(&sk, &m, &ctx).unwrap(),
            _ => sign_prehashed(&sk, &ph, &ctx).unwrap(),
        };
        assert_eq!(actual, sig, "{label}");
        let check = |s: &[u8; 64]| match mode {
            0 => verify(&pk, &m, s),
            1 => verify_ctx(&pk, &m, s, &ctx),
            _ => verify_prehashed(&pk, &ph, s, &ctx),
        };
        assert!(check(&sig), "{label}");
        assert!(
            match mode {
                0 => verify_strict(&pk, &m, &sig),
                1 => verify_ctx_strict(&pk, &m, &sig, &ctx),
                _ => verify_prehashed_strict(&pk, &ph, &sig, &ctx),
            },
            "strict {label}"
        );
        for byte in [0, 31, 32, 63] {
            let mut bad = sig;
            bad[byte] ^= 1;
            assert!(!check(&bad), "{label} corrupt {byte}");
        }
    }
}
#[test]
fn rejects_malleability_identity_noncanonical_and_wrong_domains() {
    let seed = [7; 32];
    let pk = public_key(&seed);
    let sig = sign(&seed, b"message");
    assert!(!verify(&pk, b"other", &sig));
    assert!(!verify_ctx(&pk, b"message", &sig, b""));
    let mut bad = sig;
    bad[32..].fill(255);
    assert!(!verify(&pk, b"message", &bad));
    let mut identity = [0; 32];
    identity[0] = 1;
    assert!(!validate_public_key(&identity));
    identity[31] = 128;
    assert!(!validate_public_key(&identity));
    assert!(!validate_public_key(&[255; 32]));
    assert!(sign_ctx(&seed, b"", &[0; 256]).is_err());
    assert!(!verify_ctx(&pk, b"", &sig, &[0; 256]));
    let ctx = sign_ctx(&seed, b"message", &[1; 255]).unwrap();
    assert!(verify_ctx(&pk, b"message", &ctx, &[1; 255]));
}
