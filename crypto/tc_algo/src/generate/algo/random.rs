use rand_core::CryptoRng;

// What a key must keep to besides being random: DES and DESede, as Bouncy Castle's DesKeyGenerator
// and DesEdeKeyGenerator, set the parity bits and draw again for a weak key, and for DESede again
// for a key whose parts repeat, which is DES in disguise
#[derive(Clone, Copy)]
pub(super) enum Rule {
    #[allow(dead_code, reason = "unused when only DES or DESede is on")]
    Random,
    #[cfg(feature = "des")]
    Des,
    #[cfg(feature = "desede")]
    DesEde,
}

// Random bytes of `len`, kept to `rule`
pub(super) fn random_key(rand: &mut dyn CryptoRng, len: usize, rule: Rule) -> Vec<u8> {
    let mut key = vec![0; len];
    loop {
        rand.fill_bytes(&mut key);
        let done = match rule {
            Rule::Random => true,
            #[cfg(feature = "des")]
            Rule::Des => {
                tc_des::set_odd_parity(&mut key);
                !tc_des::is_weak_key(key.as_slice().try_into().expect("8 bytes"))
            }
            #[cfg(feature = "desede")]
            Rule::DesEde => {
                tc_des::set_odd_parity(&mut key);
                !tc_des::is_weak_ede_key(&key) && tc_des::is_real_ede_key(&key)
            }
        };
        if done {
            return key;
        }
    }
}
