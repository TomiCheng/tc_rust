//! The Integrated Encryption Scheme, after Bouncy Castle's `IesEngine`: a key agreement gives
//! a shared secret, a KDF turns it into an encryption key and a MAC key, and the message is
//! encrypted and tagged with them.

#![no_std]
