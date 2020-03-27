use crate::{
    crypto::{
        aes::{self, cbc},
        misc,
    },
    utils, Result,
};

use std::collections::HashMap;

/// Set 2 - Challenge 9
/// Implement PKCS#7 padding
pub fn implement_pkcs7_padding<I: AsRef<[u8]>>(input: I) -> Vec<u8> {
    misc::pkcs7(input, 20)
}

/// Set 2 - Challenge 10
/// Implement CBC mode
pub fn implement_cbc_mode<I: AsRef<[u8]>>(input: I) -> Result<String> {
    Ok(String::from_utf8(cbc::decrypt(
        utils::from_base64(input)?,
        b"YELLOW SUBMARINE",
        None,
    )?)?)
}

/// Set 2 - Challenge 11
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

/// Set 2 - Challenge 12
/// Byte-at-a-time ECB decryption (Simple)
pub fn byte_at_a_time_ecb_decryption() -> Result<String> {
    // The oracle function that we will use to crack the encryption
    let oracle = |i: &[u8]| aes::encrypt_seeded(i, 0xdeadbeef).unwrap();

    // Discover the cipher's block size (should be 16)
    let bs = misc::discover_block_size(oracle);
    assert_eq!(bs, 16);

    // Ensure we are using ECB
    assert!(aes::is_ecb_encrypted(oracle(&vec![0; bs * 3])));

    // Allocate enough space for the deciphered text
    let mut deciphered = vec![0u8; oracle(&[]).len()];

    // Break the ciphertext one byte at a time
    for blk_id in 0..deciphered.len() / bs as usize {
        let base = blk_id * bs;
        let end = (blk_id + 1) * bs;

        for i in 0..bs {
            let n = bs - i;

            let mut test_vec = if blk_id == 0 {
                [&vec![0; n - 1], &deciphered[..=i]].concat()
            } else {
                deciphered[(blk_id - 1) * bs + i + 1..base + i + 1].to_vec()
            };

            // This is the ciphertext we need to match
            let hint = oracle(&vec![0; n - 1]);

            // This is every possible matching ciphertext
            let choices = (0..=255).map(|b| {
                test_vec[bs - 1] = b;
                oracle(&test_vec)[..bs].to_vec()
            });

            for (byte, choice) in choices.enumerate() {
                if choice == &hint[base..end] {
                    deciphered[base + i] = byte as u8;
                    break;
                }
            }
        }
    }

    Ok(String::from_utf8(deciphered)?)
}

/// Set 2 - Challenge 13
/// ECB cut-and-paste
pub fn ecb_cut_and_paste() -> Result<HashMap<String, String>> {
    // Random AES key that will be used for the challenge
    let key = aes::random_key();

    // Given an email, produces a valid ciphertext for that email
    let oracle = |email: &str| aes::ecb::encrypt(utils::profile_for(email), key, true);

    // Given a valid ciphertext, produces the kv-encoded profile
    let decrypt = |ct: &[u8]| -> Result<_> {
        utils::parse_kv_encoded(String::from_utf8(aes::ecb::decrypt(ct, key, true)?)?)
    };

    // Let's assume AES-128-ECB, which means 16-byte blocks.
    //
    // In order to craft a ciphertext which will decrypt into an admin role, we
    // need to know how to encrypt the 'admin' string, correctly padded. This is
    // the plaintext we need to encrypt:
    //
    // admin\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}
    //
    // This can be achieved by crafting an email which puts the above string
    // in its own block.

    let malicious_mail = "foooooooo@admin\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}";
    let crafted_block = oracle(malicious_mail)?[16..32].to_vec();

    // Once we have this building block, all we need to do is craft an email
    // long enough that the 'admin' string is in its own (last) block.
    //
    // An email that matches this criterion is, appropriately, break@dat.com.

    let crafted_mail = "break@dat.com";
    let valid_blocks = oracle(crafted_mail)?[..32].to_vec();

    // Finally we stitch together the desired ciphertext.

    let crafted_ciphertext = [valid_blocks, crafted_block].concat();

    // Decrypting this ciphertext gives us an admin profile.

    Ok(decrypt(&crafted_ciphertext)?)
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

    #[test]
    fn run_byte_at_a_time_ecb_decryption() {
        assert_eq!(
            byte_at_a_time_ecb_decryption().unwrap(),
            "Rollin' in my 5.0\n\
             With my rag-top down so my hair can blow\n\
             The girlies on standby waving just to say hi\n\
             Did you stop? No, I just drove by\n\
             \u{1}\u{0}\u{0}\u{0}\u{0}\u{0}"
        );
    }

    #[test]
    fn run_ecb_cut_and_paste() {
        assert_eq!(ecb_cut_and_paste().unwrap()["role"], "admin");
    }
}
