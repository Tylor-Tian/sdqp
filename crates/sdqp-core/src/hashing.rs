use sha2::{Digest, Sha256};

pub fn compute_sha256_hex(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    hex::encode(digest)
}

#[cfg(test)]
mod tests {
    use super::compute_sha256_hex;

    #[test]
    fn hashing_is_stable() {
        assert_eq!(
            compute_sha256_hex("sdqp-phase0"),
            "fd5f2867d6b259bdb3c5c6bc2b2732474bfb40e0f3e83cbadcad4b3c5ca26e98"
        );
    }
}
