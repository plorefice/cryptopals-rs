use crate::utils;

/// Set 2 - Challenge 1
/// Implement PKCS#7 padding
pub fn implement_pkcs7_padding<I: AsRef<[u8]>>(input: I) -> Vec<u8> {
    utils::pkcs7(input, 20)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_implement_pkcs7_padding() {
        assert_eq!(
            implement_pkcs7_padding(b"YELLOW SUBMARINE"),
            b"YELLOW SUBMARINE\x04\x04\x04\x04"
        );
    }
}
