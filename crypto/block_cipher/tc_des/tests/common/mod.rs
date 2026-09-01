use tc_params::KeyParams;

pub struct Key<'a>(pub &'a [u8]);

impl KeyParams for Key<'_> {
    fn key(&self) -> &[u8] {
        self.0
    }
}

#[allow(dead_code)]
pub fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}
