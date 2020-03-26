use crate::{
    crypto::{
        aes::{self, cbc},
        misc,
    },
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

/// Set 3 - Challenge 3
/// An ECB/CBC detection oracle
pub fn ecb_cbc_detection_oracle() -> Result<bool> {
    let test_vec = vec![0x42_u8; 48];

    for _ in 0..50 {
        let (is_ecb, output) = aes::encrypt_random(&test_vec)?;
        if aes::is_ecb_encrypted(output) != is_ecb {
            return Ok(false);
        }
    }

    Ok(true)
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

    #[test]
    fn run_ecb_cbc_detection_oracle() {
        assert!(ecb_cbc_detection_oracle().unwrap());
    }
}
