use crate::{crypto::misc, text, utils, Result};

use itertools::Itertools;
use openssl::symm::{self, Cipher};

/// Set 1 - Challenge 1
/// Convert hex to base64
pub fn hex_to_base64<I: AsRef<[u8]>>(input: I) -> Result<String> {
    Ok(base64::encode(hex::decode(input)?))
}

/// Set 1 - Challenge 2
/// Fixed XOR
pub fn fixed_xor<I: AsRef<[u8]>>(a: I, b: I) -> Result<String> {
    let a = hex::decode(a)?;
    let b = hex::decode(b)?;

    Ok(hex::encode(misc::xor(a, b)))
}

/// Set 1 - Challenge 3
/// Single-byte XOR cipher
pub fn xor_cipher<I: AsRef<[u8]>>(input: I) -> Result<(u8, String, f32)> {
    let mut plaintext = String::new();
    let mut best_score = 0.0;
    let mut best_key = 0;

    for key in 0u8..=255 {
        let decoded = misc::xor(input.as_ref(), &[key][..]);

        if let Ok(s) = String::from_utf8(decoded) {
            let score = text::englishness(&s);
            if score > best_score {
                best_score = score;
                best_key = key;
                plaintext = s;
            }
        }
    }

    Ok((best_key, plaintext, best_score))
}

/// Set 1 - Challenge 4
/// Detect single-character XOR
pub fn single_character_xor<I: AsRef<[u8]>>(input: I) -> Result<String> {
    let lines = input.as_ref().split(|&c| c == b'\n');

    let mut plaintext = String::new();
    let mut best_score = 0.0;

    for line in lines {
        if let Ok((_, decoded, score)) = xor_cipher(hex::decode(line)?) {
            if score > best_score {
                plaintext = decoded;
                best_score = score;
            }
        }
    }

    Ok(plaintext)
}

/// Set 1 - Challenge 5
/// Implement repeating-key XOR
pub fn repeating_key_xor<I: AsRef<[u8]>>(input: I, key: I) -> String {
    hex::encode(misc::xor(input, key))
}

/// Set 1 - Challenge 6
/// Break repeating-key XOR
pub fn break_repeating_key_xor<I: AsRef<[u8]>>(input: I) -> Result<String> {
    let input = utils::from_base64(input)?;

    // Compute likely keysizes by computing the normalized hamming distance
    // over `n_chunks` chunks, and taking the 3 sizes with higher score (lower distance).
    let n_chunks = 4;
    let sizes = (2..40)
        .map(|ks| {
            let chunks = input.chunks(ks);
            (
                ks,
                chunks
                    .clone()
                    .take(n_chunks)
                    .zip(chunks.skip(1).take(n_chunks))
                    .map(|(a, b)| utils::hamming(a, b) as f32)
                    .sum::<f32>()
                    / n_chunks as f32
                    / ks as f32,
            )
        })
        .sorted_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
        .map(|(x, _)| x)
        .take(3)
        .collect::<Vec<_>>();

    // For each likely keysize...
    let key = sizes
        .into_iter()
        .map(|sz| {
            // Transpose the blocks
            let blocks = (0..sz)
                .map(|i| {
                    input
                        .iter()
                        .skip(i)
                        .step_by(sz)
                        .cloned()
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();

            // Obtain the likely key by breaking single-byte XOR for each block
            let key = blocks
                .into_iter()
                .map(|block| xor_cipher(block).unwrap().0)
                .collect::<Vec<_>>();

            // Compute the final score on the deciphered text
            let score = text::englishness(misc::xor(&input, &key));

            (key, score)
        })
        .sorted_by(|a, b| b.1.partial_cmp(&a.1).unwrap())
        .nth(0)
        .unwrap()
        .0;

    Ok(String::from_utf8(key)?)
}

/// Set 1 - Challenge 7
/// AES in ECB mode
pub fn aes_in_ecb_mode<I: AsRef<[u8]>>(input: I) -> Result<String> {
    let input = utils::from_base64(input)?;

    Ok(String::from_utf8(symm::decrypt(
        Cipher::aes_128_ecb(),
        b"YELLOW SUBMARINE",
        None,
        &input,
    )?)?)
}

/// Set 1 - Challenge 8
/// Detect AES in ECB mode
pub fn detect_aes_in_ecb_mode<I: AsRef<[u8]>>(input: I) -> Result<String> {
    for line in input.as_ref().split(|&b| b == b'\n') {
        let line = hex::decode(line)?;

        for pair in line.chunks(16).combinations(2) {
            if pair[0] == pair[1] {
                return Ok(hex::encode(line));
            }
        }
    }
    Err("Ciphertext not detected!".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_hex_to_base64() {
        assert_eq!(
            hex_to_base64(
                &b"49276d206b696c6c696e6720796f757220627261696e206c\
                   696b65206120706f69736f6e6f7573206d757368726f6f6d"[..]
            )
            .unwrap(),
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );
    }

    #[test]
    fn run_fixed_xor() {
        assert_eq!(
            fixed_xor(
                &b"1c0111001f010100061a024b53535009181c"[..],
                &b"686974207468652062756c6c277320657965"[..]
            )
            .unwrap(),
            "746865206b696420646f6e277420706c6179"
        )
    }

    #[test]
    fn run_xor_cipher() {
        assert_eq!(
            xor_cipher(
                hex::decode(
                    &b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"[..]
                )
                .unwrap()
            )
            .unwrap()
            .1,
            "Cooking MC's like a pound of bacon"
        )
    }

    #[test]
    fn run_single_character_xor() {
        assert_eq!(
            single_character_xor(&include_bytes!("../../data/set1/4.txt")[..]).unwrap(),
            "Now that the party is jumping\n"
        )
    }

    #[test]
    fn run_repeating_key_xor() {
        assert_eq!(
            repeating_key_xor(
                &b"Burning 'em, if you ain't quick and nimble\n\
                I go crazy when I hear a cymbal"[..],
                b"ICE"
            ),
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
             a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        );
    }

    #[test]
    fn run_breaking_repeating_key_xor() {
        assert_eq!(
            break_repeating_key_xor(&include_bytes!("../../data/set1/6.txt")[..]).unwrap(),
            "Terminator X: Bring the noise"
        )
    }

    #[test]
    fn run_aes_in_ecb_mode() {
        assert!(
            aes_in_ecb_mode(&include_bytes!("../../data/set1/7.txt")[..],)
                .unwrap()
                .contains("Play that funky music")
        );
    }

    #[test]
    fn run_detect_aes_in_ecb_mode() {
        assert_eq!(
            detect_aes_in_ecb_mode(&include_bytes!("../../data/set1/8.txt")[..]).unwrap(),
            "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf\
             9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a\
             08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4f\
             d5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"
        )
    }
}
