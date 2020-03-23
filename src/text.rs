/// These are estimated character frequencies for the English language.
const ENGLISH_LETTER_FREQUENCIES: [f32; 26] = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.1270, 0.02228, 0.02015, 0.06094, 0.06966, 0.00153,
    0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056,
    0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.00074,
];

/// Computes how much a text "looks like" English.
///
/// `englishness()` will return a number in the range `[0.0, 1.0]`, where
/// `0.0` means "totally unlike English" and `1.0` means "exactly like English".
///
/// The score is computed using the [Bhattacharyya Coefficient].
///
/// [Bhattacharyya Coefficient]: https://en.wikipedia.org/wiki/Bhattacharyya_distance
pub fn englishness<T: AsRef<[u8]>>(text: T) -> f32 {
    let letters = text
        .as_ref()
        .iter()
        .filter_map(|b| {
            if b.is_ascii_alphabetic() {
                Some(b.to_ascii_uppercase())
            } else {
                None
            }
        })
        .fold(vec![0; 26], |mut v, c| {
            v[(c - b'A') as usize] += 1;
            v
        });

    let total = letters.iter().sum::<u32>() as f32;

    letters
        .into_iter()
        .enumerate()
        .map(|(c, n)| f32::sqrt(ENGLISH_LETTER_FREQUENCIES[c] * (n as f32 / total)))
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_text_has_low_englishness() {
        assert!(
            englishness(
                "LIVITCSWPIYVEWHEVSRIQMXLEYVEOIEWHRXEXIPFEMVEWHKVSTYLXZIXLIKIIXPIJVSZEYPERRGERIM\
                 WQLMGLMXQERIWGPSRIHMXQEREKIETXMJTPRGEVEKEITREWHEXXLEXXMZITWAWSQWXSWEXTVEPMRXRSJ\
                 GSTVRIEYVIEXCVMUIMWERGMIWXMJMGCSMWXSJOMIQXLIVIQIVIXQSVSTWHKPEGARCSXRWIEVSWIIBXV\
                 IZMXFSJXLIKEGAEWHEPSWYSWIWIEVXLISXLIVXLIRGEPIRQIVIIBGIIHMWYPFLEVHEWHYPSRRFQMXLE\
                 PPXLIECCIEVEWGISJKTVWMRLIHYSPHXLIQIMYLXSJXLIMWRIGXQEROIVFVIZEVAEKPIEWHXEAMWYEPP\
                 XLMWYRMWXSGSWRMHIVEXMSWMGSTPHLEVHPFKPEZINTCMXIVJSVLMRSCMWMSWVIRCIGXMWYMX"
            ) < 0.85
        );
    }

    #[test]
    fn english_test_has_high_englishness() {
        assert!(
            englishness(
                "HEREUPONLEGRANDAROSEWITHAGRAVEANDSTATELYAIRANDBROUGHTMETHEBEETLEFROMAGLASSCASEI\
                 NWHICHITWASENCLOSEDITWASABEAUTIFULSCARABAEUSANDATTHATTIMEUNKNOWNTONATURALISTSOF\
                 COURSEAGREATPRIZEINASCIENTIFICPOINTOFVIEWTHEREWERETWOROUNDBLACKSPOTSNEARONEEXTR\
                 EMITYOFTHEBACKANDALONGONENEARTHEOTHERTHESCALESWEREEXCEEDINGLYHARDANDGLOSSYWITHA\
                 LLTHEAPPEARANCEOFBURNISHEDGOLDTHEWEIGHTOFTHEINSECTWASVERYREMARKABLEANDTAKINGALL\
                 THINGSINTOCONSIDERATIONICOULDHARDLYBLAMEJUPITERFORHISOPINIONRESPECTINGIT"
            ) > 0.99
        );
    }
}
