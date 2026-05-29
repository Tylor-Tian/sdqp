use std::fmt;

use zeroize::Zeroizing;

#[derive(Clone)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(**redacted**)")
    }
}

#[derive(Clone)]
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub fn new(value: impl Into<Vec<u8>>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    pub fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(**redacted**)")
    }
}

#[cfg(test)]
mod tests {
    use super::{SecretBytes, SecretString};

    #[test]
    fn secret_wrappers_expose_value_without_debug_leak() {
        let secret = SecretString::new("token-a");
        let bytes = SecretBytes::new(vec![1, 2, 3]);
        assert_eq!(secret.expose(), "token-a");
        assert_eq!(bytes.expose(), &[1, 2, 3]);
        assert_eq!(format!("{secret:?}"), "SecretString(**redacted**)");
    }
}
