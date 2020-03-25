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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hamming_works() {
        assert_eq!(hamming(b"this is a test", b"wokka wokka!!!"), 37);
    }
}
