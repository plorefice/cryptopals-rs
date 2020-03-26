use crate::{
    crypto::{aes::cbc, misc},
    utils, Result,
};

/// Set 2 - Challenge 1
/// Implement PKCS#7 padding
pub fn implement_pkcs7_padding<I: AsRef<[u8]>>(input: I) -> Vec<u8> {
    misc::pkcs7(input, 20)
}

/// Set 2 - Challenge 2
/// Implement CBC mode
pub fn implement_cbc_mode<I: AsRef<[u8]>>(input: I) -> Result<String> {
    Ok(String::from_utf8(cbc::decrypt(
        utils::from_base64(input)?,
        b"YELLOW SUBMARINE",
        None,
    )?)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::text;

    #[test]
    fn run_implement_pkcs7_padding() {
        assert_eq!(
            implement_pkcs7_padding(b"YELLOW SUBMARINE"),
            b"YELLOW SUBMARINE\x04\x04\x04\x04"
        );
    }

    #[test]
    fn run_implement_cbc_mode() {
        assert!(
            text::englishness(
                implement_cbc_mode(&include_bytes!("../../data/10.txt")[..]).unwrap()
            ) > 0.98,
        )
    }
}
