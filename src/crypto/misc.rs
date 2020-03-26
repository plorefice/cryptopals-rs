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
    let n = size - input.len() % size;
    input.append(&mut vec![n as u8; n]);
    input
}

/// Returns a cipher's block size.
pub fn discover_block_size<F>(f: F) -> usize
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    let base_len = f(&[0]).len();

    for i in 2.. {
        let len = f(&vec![0; i]).len();
        if len != base_len {
            return len - base_len;
        }
    }
    panic!("Block size never changed!");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aes::ecb;

    #[test]
    fn pkcs7_works() {
        assert_eq!(pkcs7(b"0000", 4), b"0000\x04\x04\x04\x04");
        assert_eq!(pkcs7(b"0000", 5), b"0000\x01");
        assert_eq!(pkcs7(b"0000", 6), b"0000\x02\x02");
        assert_eq!(pkcs7(b"0000", 7), b"0000\x03\x03\x03");
        assert_eq!(pkcs7(b"0000", 8), b"0000\x04\x04\x04\x04");

        assert_eq!(
            pkcs7(b"00000000", 8),
            b"00000000\x08\x08\x08\x08\x08\x08\x08\x08"
        );
    }

    #[test]
    fn discover_block_size_works() {
        assert_eq!(
            discover_block_size(|i| ecb::encrypt(i, b"YELLOW SUBMARINE", true).unwrap()),
            16
        );
    }
}
