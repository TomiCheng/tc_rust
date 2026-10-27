//! Bouncy Castle's `Argon2Test` vectors: the RFC 9106 and reference KATs, Argon2i hashes of both
//! versions, and the parameter checks.

use tc_pwhash::argon2::{Argon2, Argon2Error, Argon2ParamsRef, Argon2Type, Argon2Version};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn derive(params: &Argon2ParamsRef<'_>, password: &[u8], len: usize) -> Vec<u8> {
    let mut argon2 = Argon2::new();
    argon2.init(params).unwrap();
    let mut out = vec![0; len];
    argon2.generate_bytes(password, &mut out).unwrap();
    out
}

#[test]
fn specification_kats_with_secret_and_associated_data_give_their_tags() {
    let password = [0x01; 32];
    let salt = [0x02; 16];
    let secret = [0x03; 8];
    let ad = [0x04; 12];
    for (version, kind, expected) in [
        (
            Argon2Version::V13,
            Argon2Type::Argon2d,
            "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",
        ),
        (
            Argon2Version::V13,
            Argon2Type::Argon2i,
            "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
        ),
        (
            Argon2Version::V13,
            Argon2Type::Argon2id,
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
        ),
        (
            Argon2Version::V10,
            Argon2Type::Argon2d,
            "96a9d4e5a1734092c85e29f410a45914a5dd1f5cbf08b2670da68a0285abf32b",
        ),
        (
            Argon2Version::V10,
            Argon2Type::Argon2i,
            "87aeedd6517ab830cd9765cd8231abb2e647a5dee08f7c05e02fcb763335d0fd",
        ),
        (
            Argon2Version::V10,
            Argon2Type::Argon2id,
            "b64615f07789b66b645b67ee9ed3b377ae350b6bfcbb0fc95141ea8f322613c0",
        ),
    ] {
        let params = Argon2ParamsRef::new(kind, &salt)
            .with_version(version)
            .with_iterations(3)
            .with_memory_kib(32)
            .with_parallelism(4)
            .with_secret(&secret)
            .with_additional(&ad);
        assert_eq!(
            derive(&params, &password, 32),
            hex(expected),
            "{version:?} {kind:?}"
        );
    }
}

fn argon2i(
    version: Argon2Version,
    t: u32,
    m_log2: u32,
    p: u32,
    password: &str,
    salt: &str,
    len: usize,
) -> Vec<u8> {
    let params = Argon2ParamsRef::new(Argon2Type::Argon2i, salt.as_bytes())
        .with_version(version)
        .with_iterations(t)
        .with_memory_kib(1 << m_log2)
        .with_parallelism(p);
    derive(&params, password.as_bytes(), len)
}

#[test]
fn bc_argon2i_vectors_of_version_0x10_give_their_hashes() {
    let v = Argon2Version::V10;
    for (t, m, p, password, salt, expected) in [
        (
            2,
            16,
            1,
            "password",
            "somesalt",
            "f6c4db4a54e2a370627aff3db6176b94a2a209a62c8e36152711802f7b30c694",
        ),
        (
            2,
            8,
            1,
            "password",
            "somesalt",
            "fd4dd83d762c49bdeaf57c47bdcd0c2f1babf863fdeb490df63ede9975fccf06",
        ),
        (
            2,
            8,
            2,
            "password",
            "somesalt",
            "b6c11560a6a9d61eac706b79a2f97d68b4463aa3ad87e00c07e2b01e90c564fb",
        ),
        (
            1,
            16,
            1,
            "password",
            "somesalt",
            "81630552b8f3b1f48cdb1992c4c678643d490b2b5eb4ff6c4b3438b5621724b2",
        ),
        (
            4,
            16,
            1,
            "password",
            "somesalt",
            "f212f01615e6eb5d74734dc3ef40ade2d51d052468d8c69440a3a1f2c1c2847b",
        ),
        (
            2,
            16,
            1,
            "differentpassword",
            "somesalt",
            "e9c902074b6754531a3a0be519e5baf404b30ce69b3f01ac3bf21229960109a3",
        ),
        (
            2,
            16,
            1,
            "password",
            "diffsalt",
            "79a103b90fe8aef8570cb31fc8b22259778916f8336b7bdac3892569d4f1c497",
        ),
    ] {
        assert_eq!(
            argon2i(v, t, m, p, password, salt, 32),
            hex(expected),
            "{t} {m} {p} {password} {salt}"
        );
    }
}

#[test]
fn bc_argon2i_vectors_of_version_0x13_give_their_hashes() {
    let v = Argon2Version::V13;
    for (t, m, p, password, salt, expected) in [
        (
            2,
            16,
            1,
            "password",
            "somesalt",
            "c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0",
        ),
        (
            2,
            8,
            1,
            "password",
            "somesalt",
            "89e9029f4637b295beb027056a7336c414fadd43f6b208645281cb214a56452f",
        ),
        (
            2,
            8,
            2,
            "password",
            "somesalt",
            "4ff5ce2769a1d7f4c8a491df09d41a9fbe90e5eb02155a13e4c01e20cd4eab61",
        ),
        (
            1,
            16,
            1,
            "password",
            "somesalt",
            "d168075c4d985e13ebeae560cf8b94c3b5d8a16c51916b6f4ac2da3ac11bbecf",
        ),
        (
            4,
            16,
            1,
            "password",
            "somesalt",
            "aaa953d58af3706ce3df1aefd4a64a84e31d7f54175231f1285259f88174ce5b",
        ),
        (
            2,
            16,
            1,
            "differentpassword",
            "somesalt",
            "14ae8da01afea8700c2358dcef7c5358d9021282bd88663a4562f59fb74d22ee",
        ),
        (
            2,
            16,
            1,
            "password",
            "diffsalt",
            "b0357cccfbef91f3860b0dba447b2348cbefecadaf990abfe9cc40726c521271",
        ),
    ] {
        assert_eq!(
            argon2i(v, t, m, p, password, salt, 32),
            hex(expected),
            "{t} {m} {p} {password} {salt}"
        );
    }
}

#[test]
#[ignore = "needs 256 MiB and 1 GiB, slow in debug; run with --release"]
fn bc_argon2i_vectors_with_large_memory_give_their_hashes() {
    for (version, m, expected) in [
        (
            Argon2Version::V10,
            20,
            "9690ec55d28d3ed32562f2e73ea62b02b018757643a2ae6e79528459de8106e9",
        ),
        (
            Argon2Version::V10,
            18,
            "3e689aaa3d28a77cf2bc72a51ac53166761751182f1ee292e3f677a7da4c2467",
        ),
        (
            Argon2Version::V13,
            20,
            "d1587aca0922c3b5d6a83edab31bee3c4ebaef342ed6127a55d19b2351ad1f41",
        ),
        (
            Argon2Version::V13,
            18,
            "296dbae80b807cdceaad44ae741b506f14db0959267b183b118f9b24229bc7cb",
        ),
    ] {
        assert_eq!(
            argon2i(version, 2, m, 1, "password", "somesalt", 32),
            hex(expected),
            "{version:?} {m}"
        );
    }
}

#[test]
fn outputs_over_64_bytes_chain_blake2b_as_h_prime_does() {
    assert_eq!(
        argon2i(Argon2Version::V10, 2, 16, 1, "password", "diffsalt", 112),
        hex(concat!(
            "1a097a5d1c80e579583f6e19c7e4763ccb7c522ca85b7d58143738e12ca39f8e6e42734c950ff2463675b97c37ba",
            "39feba4a9cd9cc5b4c798f2aaf70eb4bd044c8d148decb569870dbd923430b82a083f284beae777812cce18cdac68ee8ccef",
            "c6ec9789f30a6b5a034591f51af830f4",
        ))
    );
}

#[test]
fn a_generator_gives_the_same_tag_again_and_takes_new_parameters_on_init() {
    let salt = *b"somesalt";
    let small = Argon2ParamsRef::new(Argon2Type::Argon2i, &salt)
        .with_iterations(2)
        .with_memory_kib(256);
    let two_lanes = small.with_parallelism(2);
    let mut argon2 = Argon2::new();
    let mut first = [0; 32];
    let mut again = [0; 32];

    argon2.init(&small).unwrap();
    argon2.generate_bytes(b"password", &mut first).unwrap();
    argon2.generate_bytes(b"password", &mut again).unwrap();
    assert_eq!(first, again);
    assert_eq!(
        first.to_vec(),
        hex("89e9029f4637b295beb027056a7336c414fadd43f6b208645281cb214a56452f")
    );

    argon2.init(&two_lanes).unwrap();
    argon2.generate_bytes(b"password", &mut again).unwrap();
    assert_eq!(
        again.to_vec(),
        hex("4ff5ce2769a1d7f4c8a491df09d41a9fbe90e5eb02155a13e4c01e20cd4eab61")
    );
}

#[test]
fn bad_parameters_fail_at_init_and_bad_outputs_at_generation() {
    let salt = [0; 16];
    let params = Argon2ParamsRef::new(Argon2Type::Argon2id, &salt);
    let mut argon2 = Argon2::new();

    assert_eq!(
        argon2.generate_bytes(b"pw", &mut [0; 32]),
        Err(Argon2Error::NotInitialised)
    );
    assert_eq!(
        argon2.init(&params.with_parallelism(0)),
        Err(Argon2Error::InvalidParallelism(0))
    );
    assert_eq!(
        argon2.init(&params.with_parallelism(1 << 24)),
        Err(Argon2Error::InvalidParallelism(1 << 24))
    );
    assert_eq!(
        argon2.init(&params.with_iterations(0)),
        Err(Argon2Error::InvalidIterations(0))
    );
    assert_eq!(
        argon2.init(&params.with_memory_kib(0)),
        Err(Argon2Error::InvalidMemory(0))
    );

    argon2.init(&params.with_memory_kib(8)).unwrap();
    assert_eq!(
        argon2.generate_bytes(b"pw", &mut [0; 3]),
        Err(Argon2Error::InvalidOutputLength(3))
    );
    assert_eq!(argon2.generate_bytes(b"pw", &mut [0; 4]), Ok(()));
}

#[test]
fn memory_under_eight_blocks_per_lane_is_raised_but_still_hashed_as_given() {
    let salt = [0; 16];
    let base = Argon2ParamsRef::new(Argon2Type::Argon2d, &salt)
        .with_iterations(1)
        .with_parallelism(2);
    let one = derive(&base.with_memory_kib(1), b"pw", 32);
    let sixteen = derive(&base.with_memory_kib(16), b"pw", 32);
    assert_ne!(one, sixteen);
}
