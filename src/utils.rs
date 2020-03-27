use crate::Result;

use std::collections::HashMap;

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

/// Generates a key-value-encoded profile string for the specified email.
///
/// The email is sanitized before encoding, by stripping & and = characters.
pub fn profile_for<I: AsRef<str>>(email: I) -> String {
    // Sanitize email
    let email = email
        .as_ref()
        .chars()
        .filter(|&c| c != '&' && c != '=')
        .collect::<String>();

    format!("email={}&uid=10&role=user", email)
}

/// Parses a key-value-encoded profile string into its components.
pub fn parse_kv_encoded<I: AsRef<str>>(s: I) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    for pairs in s.as_ref().split('&') {
        let mut kv = pairs.split('=');
        map.insert(
            kv.next().ok_or("Missing key")?.to_owned(),
            kv.next().ok_or("Missing value")?.to_owned(),
        );
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::iter::FromIterator;

    #[test]
    fn hamming_works() {
        assert_eq!(hamming(b"this is a test", b"wokka wokka!!!"), 37);
    }

    #[test]
    fn profile_for_works() {
        for (email, out) in vec![
            ("", "email=&uid=10&role=user"),
            ("foo", "email=foo&uid=10&role=user"),
            ("foo&role", "email=foorole&uid=10&role=user"),
            ("role=admin", "email=roleadmin&uid=10&role=user"),
            ("foo@bar.com", "email=foo@bar.com&uid=10&role=user"),
            (
                "foo@bar.com&role=admin",
                "email=foo@bar.comroleadmin&uid=10&role=user",
            ),
        ]
        .into_iter()
        {
            assert_eq!(profile_for(email), out);
        }
    }

    #[test]
    fn parse_kv_encoded_works() {
        assert_eq!(
            parse_kv_encoded("email=foo@bar.com&uid=10&role=user").unwrap(),
            HashMap::from_iter(
                [
                    ("email".to_string(), "foo@bar.com".to_string()),
                    ("uid".to_string(), "10".to_string()),
                    ("role".to_string(), "user".to_string())
                ]
                .iter()
                .cloned()
            )
        );
    }
}
