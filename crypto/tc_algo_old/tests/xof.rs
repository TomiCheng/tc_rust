#![cfg(all(
    feature = "shake",
    feature = "cshake",
    feature = "tuplehash",
    feature = "parallelhash",
    feature = "blake2xs",
    feature = "blake3",
    feature = "ascon-xof128",
    feature = "ascon-cxof128",
    feature = "ascon-xof-legacy",
))]

// Every XOF against the output Bouncy Castle's classes gave, and what each refuses
#[path = "vectors/bc_xofs.rs"]
mod bc_xofs;

use bc_xofs::VECTORS;
use tc_algo_old::{Algo, AnyXofParams, ErrorKind, Policy};
use tc_asn1::Asn1Oid;

const NAMES: [&str; 14] = [
    "SHAKE128",
    "SHAKE256",
    "CSHAKE128",
    "CSHAKE256",
    "TUPLEHASH128",
    "TUPLEHASH256",
    "PARALLELHASH128",
    "PARALLELHASH256",
    "BLAKE2XS",
    "BLAKE3",
    "ASCON-XOF128",
    "ASCON-CXOF128",
    "ASCON-XOF",
    "ASCON-XOFA",
];

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

#[test]
fn every_output_is_the_one_bouncy_castle_gave() {
    assert!(VECTORS.len() > 500);
    let algo = Algo::new();
    for &(name, customization, function_name, block, message, split, expected) in VECTORS {
        let mut params = AnyXofParams::new();
        if !customization.is_empty() {
            params = params.with_customization(unhex(customization));
        }
        if !function_name.is_empty() {
            params = params.with_function_name(unhex(function_name));
        }
        if block != 0 {
            params = params.with_block_size(block);
        }
        let expected = unhex(expected);

        let mut xof = algo.xof().get_by_name(name).unwrap();
        xof.init(&params).unwrap();
        for piece in message.split('|') {
            xof.update(&unhex(piece)).unwrap();
        }
        // Calling output at all makes TupleHash and ParallelHash their XOF forms, as in Bouncy Castle
        let mut output = vec![0; split];
        if split > 0 {
            xof.output(&mut output).unwrap();
        }
        output.extend(xof.finalize(expected.len() - split).unwrap());
        assert_eq!(
            output, expected,
            "{name} s={customization} n={function_name} b={block}"
        );
    }
}

#[test]
fn every_row_has_a_vector() {
    let algo = Algo::new();
    let listed: Vec<&str> = algo.xof().algorithms().map(|entry| entry.name()).collect();
    assert_eq!(listed, NAMES);
    for name in NAMES {
        assert!(VECTORS.iter().any(|vector| vector.0 == name), "{name}");
    }
}

#[test]
fn names_and_the_oids_of_shake_find_their_rows() {
    let algo = Algo::new();
    for (name, row) in [
        ("shake128", "SHAKE128"),
        ("SHAKE-256", "SHAKE256"),
        ("ascon-cxof128", "ASCON-CXOF128"),
        ("2.16.840.1.101.3.4.2.11", "SHAKE128"),
    ] {
        assert_eq!(algo.xof().get_by_name(name).unwrap().entry().name(), row);
    }
    let oid: Asn1Oid = "2.16.840.1.101.3.4.2.12".parse().unwrap();
    assert_eq!(
        algo.xof().get_by_oid(&oid).unwrap().entry().name(),
        "SHAKE256"
    );
}

#[test]
fn an_unknown_name_or_oid_is_reported_as_an_unknown_xof() {
    let algo = Algo::new();
    let oid: Asn1Oid = "1.2.3.4".parse().unwrap();
    assert_eq!(
        algo.xof().get_by_name("SHA-256").unwrap_err().kind(),
        ErrorKind::UnknownXof
    );
    assert_eq!(
        algo.xof().get_by_oid(&oid).unwrap_err().kind(),
        ErrorKind::UnknownXof
    );
}

#[test]
fn finalize_starts_the_next_message_under_the_same_params() {
    let algo = Algo::new();
    let params = AnyXofParams::new().with_customization(b"tag".to_vec());
    let mut xof = algo.xof().get_by_name("CSHAKE128").unwrap();
    xof.init(&params).unwrap();
    xof.update(b"message").unwrap();
    let first = xof.finalize(32).unwrap();
    xof.update(b"message").unwrap();
    assert_eq!(xof.finalize(32).unwrap(), first);
}

#[test]
fn input_after_output_began_is_refused_until_a_new_message() {
    let algo = Algo::new();
    for name in NAMES {
        let mut xof = algo.xof().get_by_name(name).unwrap();
        xof.init(&params_for(name)).unwrap();
        xof.update(b"message").unwrap();
        let mut output = [0; 16];
        xof.output(&mut output).unwrap();
        assert_eq!(
            xof.update(b"more").unwrap_err().kind(),
            ErrorKind::XofOutputStarted,
            "{name}"
        );
        xof.reset();
        xof.update(b"message").unwrap();
    }
}

fn params_for(name: &str) -> AnyXofParams {
    if name.starts_with("PARALLELHASH") {
        AnyXofParams::new().with_block_size(8)
    } else {
        AnyXofParams::new()
    }
}

#[test]
fn reset_discards_the_message_and_keeps_the_params() {
    let algo = Algo::new();
    let params = AnyXofParams::new().with_customization(b"tag".to_vec());
    let mut xof = algo.xof().get_by_name("TUPLEHASH128").unwrap();
    xof.init(&params).unwrap();
    xof.update(b"message").unwrap();
    let expected = xof.finalize(32).unwrap();

    xof.update(b"other").unwrap();
    xof.reset();
    xof.update(b"message").unwrap();
    assert_eq!(xof.finalize(32).unwrap(), expected);
}

#[test]
fn an_xof_that_takes_nothing_is_ready_without_init() {
    let algo = Algo::new();
    for name in NAMES {
        if name.starts_with("PARALLELHASH") {
            continue;
        }
        let mut xof = algo.xof().get_by_name(name).unwrap();
        xof.update(b"message").unwrap();
        assert_eq!(xof.finalize(16).unwrap().len(), 16, "{name}");
    }
}

#[test]
fn parallelhash_needs_a_block_size_above_zero() {
    let algo = Algo::new();
    let mut xof = algo.xof().get_by_name("PARALLELHASH128").unwrap();
    assert_eq!(
        xof.update(b"message").unwrap_err().kind(),
        ErrorKind::NotInitialized
    );
    assert_eq!(
        xof.finalize(16).unwrap_err().kind(),
        ErrorKind::NotInitialized
    );
    assert_eq!(
        xof.init(&AnyXofParams::new()).unwrap_err().kind(),
        ErrorKind::InvalidParams
    );
    assert_eq!(
        xof.init(&AnyXofParams::new().with_block_size(0))
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidParams
    );
    assert!(xof.init(&AnyXofParams::new().with_block_size(1)).is_ok());
}

#[test]
fn a_field_the_xof_has_no_use_for_is_refused() {
    let algo = Algo::new();
    for (name, params) in [
        ("SHAKE128", AnyXofParams::new().with_customization(vec![1])),
        ("BLAKE3", AnyXofParams::new().with_customization(vec![1])),
        (
            "TUPLEHASH128",
            AnyXofParams::new().with_function_name(vec![1]),
        ),
        ("CSHAKE128", AnyXofParams::new().with_block_size(8)),
        ("ASCON-XOF128", AnyXofParams::new().with_block_size(8)),
    ] {
        let mut xof = algo.xof().get_by_name(name).unwrap();
        assert_eq!(
            xof.init(&params).unwrap_err().kind(),
            ErrorKind::InvalidParams,
            "{name}"
        );
    }
}

#[test]
fn a_refused_init_never_goes_on_under_the_earlier_params() {
    let algo = Algo::new();
    let mut plain = algo.xof().get_by_name("CSHAKE128").unwrap();
    plain.update(b"message").unwrap();
    let expected = plain.finalize(32).unwrap();

    let mut xof = algo.xof().get_by_name("CSHAKE128").unwrap();
    xof.init(&AnyXofParams::new().with_customization(b"tag".to_vec()))
        .unwrap();
    assert!(xof.init(&AnyXofParams::new().with_block_size(8)).is_err());
    xof.update(b"message").unwrap();
    assert_eq!(xof.finalize(32).unwrap(), expected);
}

#[test]
fn ascon_cxof128_refuses_a_customization_over_256_bytes() {
    let algo = Algo::new();
    let mut xof = algo.xof().get_by_name("ASCON-CXOF128").unwrap();
    assert!(
        xof.init(&AnyXofParams::new().with_customization(vec![0; 256]))
            .is_ok()
    );
    assert_eq!(
        xof.init(&AnyXofParams::new().with_customization(vec![0; 257]))
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidParams
    );
}

#[test]
fn calculate_gives_what_the_steps_give() {
    let algo = Algo::new();
    let params = AnyXofParams::new()
        .with_customization(b"tag".to_vec())
        .with_block_size(8);
    let mut xof = algo.xof().get_by_name("PARALLELHASH256").unwrap();
    xof.init(&params).unwrap();
    xof.update(b"message").unwrap();
    assert_eq!(
        algo.xof()
            .calculate("PARALLELHASH256", &params, b"message", 40)
            .unwrap(),
        xof.finalize(40).unwrap()
    );
}

#[test]
fn a_denied_xof_is_not_listed_but_can_still_be_got() {
    let mut algo = Algo::new();
    algo.set_policy(Policy::new().with_deny(["SHAKE-128"]));
    let listed: Vec<&str> = algo.xof().algorithms().map(|entry| entry.name()).collect();
    assert!(!listed.contains(&"SHAKE128"));
    assert!(listed.contains(&"SHAKE256"));
    assert!(algo.xof().get_by_name("SHAKE128").is_ok());
}

#[test]
fn debug_and_display_show_only_the_name() {
    let algo = Algo::new();
    let mut xof = algo.xof().get_by_name("SHAKE128").unwrap();
    xof.update(b"message").unwrap();
    assert_eq!(xof.to_string(), "SHAKE128");
    assert_eq!(format!("{xof:?}"), "AnyXof { name: \"SHAKE128\", .. }");
    assert_eq!(xof.entry().to_string(), "SHAKE128  [id-shake128]");
}
