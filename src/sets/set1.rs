use crate::Result;

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

    Ok(hex::encode(
        a.into_iter().zip(b).map(|(a, b)| a ^ b).collect::<Vec<_>>(),
    ))
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
}
