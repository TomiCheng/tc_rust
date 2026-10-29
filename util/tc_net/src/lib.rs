//! IPv4 與 IPv6 位址驗證，對應 Bouncy Castle 的 `Utilities.Net`。
//!
//! ```
//! use tc_net::ip_address;
//!
//! assert!(ip_address::is_valid("192.168.0.1"));
//! assert!(ip_address::is_valid_with_netmask("2001:db8::/32"));
//! ```

#![no_std]

pub mod ip_address;
