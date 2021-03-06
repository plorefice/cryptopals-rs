use crate::{utils, Result};

use rand::{distributions::Standard, random, rngs::StdRng, thread_rng, Rng, SeedableRng};

pub mod ecb {
    use super::Result;

    use openssl::symm::{self, Cipher};

    pub fn encrypt<I, K>(input: I, key: K, pad: bool) -> Result<Vec<u8>>
    where
        I: AsRef<[u8]>,
        K: AsRef<[u8]>,
    {
        let input = input.as_ref();
        let cipher = Cipher::aes_128_ecb();

        let mut output = vec![0; input.len() + cipher.block_size()];
        let mut c = symm::Crypter::new(cipher, symm::Mode::Encrypt, key.as_ref(), None)?;

        c.pad(pad);

        let mut written = c.update(input, &mut output)?;
        written += c.finalize(&mut output[written..])?;

        output.drain(written..);

        Ok(output)
    }

    pub fn decrypt<I, K>(input: I, key: K, pad: bool) -> Result<Vec<u8>>
    where
        I: AsRef<[u8]>,
        K: AsRef<[u8]>,
    {
        let input = input.as_ref();
        let cipher = Cipher::aes_128_ecb();

        let mut output = vec![0; input.len() + cipher.block_size()];
        let mut c = symm::Crypter::new(cipher, symm::Mode::Decrypt, key.as_ref(), None)?;

        c.pad(pad);

        let mut written = c.update(input, &mut output)?;
        written += c.finalize(&mut output[written..])?;

        output.drain(written..);

        Ok(output)
    }
}

pub mod cbc {
    use super::{ecb, Result};
    use crate::crypto::misc;

    pub fn encrypt<I, K>(input: I, key: K, iv: Option<&[u8]>) -> Result<Vec<u8>>
    where
        I: AsRef<[u8]>,
        K: AsRef<[u8]>,
    {
        let key = key.as_ref();
        let n = key.len();

        let input = misc::pkcs7(input.as_ref(), n as u8);
        let iv = iv.map(|iv| iv.to_owned()).unwrap_or(vec![0; n]);

        let mut ciphertext = Vec::with_capacity(input.len());

        for (i, block) in input.chunks(n).enumerate() {
            let chunk = misc::xor(
                block.as_ref(),
                if i == 0 {
                    iv.as_ref()
                } else {
                    &ciphertext[(i - 1) * n..i * n]
                },
            );

            ciphertext.extend(ecb::encrypt(chunk, key, false)?);
        }

        Ok(ciphertext)
    }

    pub fn decrypt<I, K>(input: I, key: K, iv: Option<&[u8]>) -> Result<Vec<u8>>
    where
        I: AsRef<[u8]>,
        K: AsRef<[u8]>,
    {
        let input = input.as_ref();
        let key = key.as_ref();
        let n = key.len();

        let iv = iv.map(|iv| iv.to_owned()).unwrap_or(vec![0; n]);

        let mut plaintext = ecb::decrypt(input, key, false)?;

        for (i, block) in plaintext.chunks_mut(n).enumerate() {
            block.copy_from_slice(&misc::xor(
                block.as_ref(),
                if i == 0 {
                    iv.as_ref()
                } else {
                    &input[(i - 1) * n..i * n]
                },
            ));
        }

        Ok(plaintext)
    }
}

/// Generates a random AES-128 key.
pub fn random_key() -> [u8; 16] {
    rand::random()
}

/// Generates a random AES-128 key from the specified seed.
pub fn seeded_key(seed: u64) -> [u8; 16] {
    let mut rng = StdRng::seed_from_u64(seed);
    rng.gen()
}

/// Generates a random number of bytes in the range `[min, max]`.
fn random_bytes(min: usize, max: usize) -> Vec<u8> {
    thread_rng()
        .sample_iter::<u8, _>(Standard)
        .take(thread_rng().gen_range(min, max + 1))
        .collect()
}

/// Encrypts data with AES-128 using random parameters.
///
/// The data is first prefixed and suffixed with 5-10 random bytes each.
/// It is then encrypted with a randomly chosen key, using either ECB
/// or CBC (with random IVs) with equal probability.
///
/// Returns whether ECB was used, and the encrypted data.
pub fn encrypt_random<I: AsRef<[u8]>>(input: I) -> Result<(bool, Vec<u8>)> {
    let mut input = input.as_ref().to_vec();

    // Generate random encryption key and IVs
    let key = random_key();
    let iv = random_key();

    // Add variable-length random prefix and suffix to the plaintext
    input.splice(0..0, random_bytes(5, 10));
    input.extend(random_bytes(5, 10));

    // Encrypt half the time using ECB and half the time using CBC
    let res = if random::<bool>() {
        (true, ecb::encrypt(input, key, true)?)
    } else {
        (false, cbc::encrypt(input, key, Some(&iv))?)
    };

    Ok(res)
}

/// Encrypts data with AES-128-ECB using a random key generated from the seed.
///
/// The input is affixed with a fixed, unknown string before encryption.
pub fn encrypt_seeded<I: AsRef<[u8]>>(input: I, seed: u64) -> Result<Vec<u8>> {
    let mut input = input.as_ref().to_vec();

    // Trailing unknown text that we need to decrypt
    let suffix = utils::from_base64(
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
         aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
         dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
         YnkK",
    )?;

    // Generate encryption key from seed
    let key = seeded_key(seed);

    // Append suffix to the input
    input.extend(suffix);

    // Encrypt using ECB
    ecb::encrypt(input, key, true)
}

/// Returns whether the input was encryptd using ECB.
pub fn is_ecb_encrypted<I: AsRef<[u8]>>(input: I) -> bool {
    input
        .as_ref()
        .chunks(16)
        .zip(input.as_ref().chunks(16).skip(1))
        .any(|(a, b)| a == b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecb_with_padding() {
        for (pt, ct) in vec![
            (&b"We all live in"[..], "3f538bb72dd0af159f18363ceb535413"),
            (
                &b"We all live in a"[..],
                "ec39ebf3d7914e8f141b8afb91d3462960fa36707e45f499dba0f25b922301a5",
            ),
            (
                &b"We all live in a yellow submarine"[..],
                "ec39ebf3d7914e8f141b8afb91d34629a1a1f92f5bca30da\
                 e57f35e708f49c8d4351d077d91e9420657dc3cd8868b376",
            ),
        ]
        .into_iter()
        {
            assert_eq!(
                hex::encode(ecb::encrypt(pt, b"YELLOW SUBMARINE", true).unwrap()),
                ct
            );
        }
    }

    #[test]
    fn ecb_without_padding() {
        for (pt, ct) in vec![
            (&b"We all live in a"[..], "ec39ebf3d7914e8f141b8afb91d34629"),
            (
                &b"We all live in a yellow submarin"[..],
                "ec39ebf3d7914e8f141b8afb91d34629\
                 a1a1f92f5bca30dae57f35e708f49c8d",
            ),
        ]
        .into_iter()
        {
            assert_eq!(
                hex::encode(ecb::encrypt(pt, b"YELLOW SUBMARINE", false).unwrap()),
                ct
            );
        }
    }

    #[test]
    fn ecb_roundtrip() {
        assert_eq!(
            ecb::decrypt(
                ecb::encrypt(
                    &b"We all live in a yellow submarine"[..],
                    b"YELLOW SUBMARINE",
                    true
                )
                .unwrap(),
                b"YELLOW SUBMARINE",
                true
            )
            .unwrap(),
            &b"We all live in a yellow submarine"[..]
        );
    }
}
