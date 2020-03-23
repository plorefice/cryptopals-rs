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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hamming_works() {
        assert_eq!(hamming(b"this is a test", b"wokka wokka!!!"), 37);
    }
}
