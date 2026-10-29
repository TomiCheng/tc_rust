use tc_net::ip_address::{
    is_valid, is_valid_ipv4, is_valid_ipv4_with_netmask, is_valid_ipv6, is_valid_ipv6_with_netmask,
    is_valid_with_netmask,
};

/// 移植自 bc-csharp 的 `Utilities.Net.Tests.IPTest`。
#[test]
fn bc_ip_test_accepts_and_rejects_the_same_addresses() {
    for valid in [
        "0.0.0.0",
        "255.255.255.255",
        "192.168.0.0",
        "0:0:0:0:0:0:0:0",
        "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF",
        "0:1:2:3:FFFF:5:FFFF:1",
    ] {
        assert!(is_valid(valid), "{valid}");
    }
    for invalid in [
        "0.0.0.0.1",
        "256.255.255.255",
        "1",
        "A.B.C",
        "1:.4.6.5",
        "0.0.0.0:1",
        "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFFF",
    ] {
        assert!(!is_valid(invalid), "{invalid}");
    }
}

#[test]
fn ipv4_octets_are_decimal_up_to_255_and_may_have_leading_zeros() {
    for valid in ["1.2.3.4", "01.02.003.4", "255.0.0.255"] {
        assert!(is_valid_ipv4(valid), "{valid}");
    }
    for invalid in [
        "",
        "1.2.3",
        "1.2.3.4.",
        ".1.2.3.4",
        "1..2.3",
        "1.2.3.256",
        "1.2.3.0004",
        "1.2.3.-1",
        "1.2.3.4 ",
        "١.٢.٣.٤",
    ] {
        assert!(!is_valid_ipv4(invalid), "{invalid}");
    }
}

#[test]
fn ipv6_allows_one_double_colon_and_a_trailing_ipv4() {
    for valid in [
        "::",
        "::1",
        "1::",
        "2001:db8::ff00:42:8329",
        "fe80::1:2:3:4:5:6",
        "::ffff:192.168.0.1",
        "0:0:0:0:0:ffff:192.168.0.1",
    ] {
        assert!(is_valid_ipv6(valid), "{valid}");
    }
    for invalid in [
        "",
        "1::2::3",
        "1:2:3:4:5:6:7",
        "1:2:3:4:5:6:7:8:9",
        "1:2:3:4:5:6:7:192.168.0.1",
        "::192.168.0.256",
        "12345::",
        "::1.2.3.4:5",
    ] {
        assert!(!is_valid_ipv6(invalid), "{invalid}");
    }
}

#[test]
fn only_real_hexadecimal_digits_are_accepted_unlike_bc() {
    // BC 的 GetDigitHexadecimal 會把這些當成數字。
    for invalid in ["g::1", "G::1", "::;", "::1:?", "0:0:0:0:0:0:0:\u{10}"] {
        assert!(!is_valid_ipv6(invalid), "{invalid:?}");
    }
}

#[test]
fn netmasks_are_an_address_or_a_prefix_length_without_leading_zeros() {
    for valid in [
        "10.0.0.0/8",
        "10.0.0.0/0",
        "10.0.0.0/32",
        "10.0.0.0/255.0.0.0",
        "2001:db8::/32",
        "2001:db8::/128",
        "2001:db8::/1",
        "2001:db8::/ffff:ffff::",
    ] {
        assert!(is_valid_with_netmask(valid), "{valid}");
    }
    for invalid in [
        "10.0.0.0",
        "/8",
        "10.0.0.0/",
        "10.0.0.0/33",
        "10.0.0.0/08",
        "2001:db8::/0",
        "2001:db8::/129",
        "2001:db8::/032",
    ] {
        assert!(!is_valid_with_netmask(invalid), "{invalid}");
    }
    assert!(!is_valid_ipv4_with_netmask("2001:db8::/32"));
    assert!(!is_valid_ipv6_with_netmask("10.0.0.0/8"));
}
