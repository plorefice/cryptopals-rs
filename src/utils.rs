use crate::Result;

/// Decodes Base64-encoded data, and returns the decoded bytes.
///
/// The input is sanitized before decoding.
pub fn from_base64<I: AsRef<[u8]>>(input: I) -> Result<Vec<u8>> {
    Ok(base64::decode(
        input
            .as_ref()
            .iter()
            .cloned()
            .filter(|c| !c.is_ascii_whitespace())
            .collect::<Vec<_>>(),
    )?)
}

/// Computes the Hamming (or edit) distance between two byte slices.
///
/// The Hamming distance is just the number of differing bits between
/// corresponding elements of the slices.
pub fn hamming<I: AsRef<[u8]>>(a: I, b: I) -> u32 {
    a.as_ref()
        .into_iter()
        .zip(b.as_ref().into_iter())
        .map(|(x, y)| (x ^ y).count_ones())
        .sum::<u32>()
}

/// Computes the element-wise XOR of two byte slices.
///
/// If `b` is shorter than `a`, it is replicated until reaching the same size.
///
/// # Panics
///
/// Panics if `a` is shorter than `b`.
pub fn xor<I: AsRef<[u8]>>(a: I, b: I) -> Vec<u8> {
    let (a, b) = (a.as_ref(), b.as_ref());

    assert!(a.len() >= b.len());

    a.into_iter()
        .zip(b.into_iter().cycle())
        .map(|(a, b)| a ^ b)
        .collect()
}

/// Pads the input to a multiple of `size` bytes by using the PKCS#7 padding scheme.
pub fn pkcs7<I: AsRef<[u8]>>(input: I, size: u8) -> Vec<u8> {
    let mut input = input.as_ref().to_owned();
    let size = usize::from(size);

    let excess = input.len() % size;

    if excess == 0 {
        input
    } else {
        let n = size - excess;
        input.append(&mut vec![n as u8; n]);
        input
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hamming_works() {
        assert_eq!(hamming(b"this is a test", b"wokka wokka!!!"), 37);
    }

    #[test]
    fn pkcs7_works() {
        assert_eq!(pkcs7(b"0000", 4), b"0000");
        assert_eq!(pkcs7(b"0000", 5), b"0000\x01");
        assert_eq!(pkcs7(b"0000", 6), b"0000\x02\x02");
        assert_eq!(pkcs7(b"0000", 7), b"0000\x03\x03\x03");
        assert_eq!(pkcs7(b"0000", 8), b"0000\x04\x04\x04\x04");
        assert_eq!(pkcs7(b"00000000", 8), b"00000000");
    }
}
