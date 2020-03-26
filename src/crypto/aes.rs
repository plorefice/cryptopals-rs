pub mod ecb {
    use crate::Result;

    use openssl::symm::{self, Cipher};

    pub fn encrypt<I, K>(input: I, key: K) -> Result<Vec<u8>>
    where
        I: AsRef<[u8]>,
        K: AsRef<[u8]>,
    {
        Ok(symm::encrypt(
            Cipher::aes_128_ecb(),
            key.as_ref(),
            None,
            input.as_ref(),
        )?)
    }

    pub fn decrypt<I, K>(input: I, key: K, pad: bool) -> Result<Vec<u8>>
    where
        I: AsRef<[u8]>,
        K: AsRef<[u8]>,
    {
        let cipher = Cipher::aes_128_ecb();

        let mut output = vec![0; input.as_ref().len() + cipher.block_size()];
        let mut c = symm::Crypter::new(cipher, symm::Mode::Decrypt, key.as_ref(), None)?;

        c.pad(pad);

        let mut written = c.update(input.as_ref(), &mut output)?;
        written += c.finalize(&mut output)?;

        output.drain(written..);

        Ok(output)
    }
}

pub mod cbc {
    use super::ecb;
    use crate::{crypto::misc, Result};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecb_roundtrip() {
        assert_eq!(
            ecb::decrypt(
                ecb::encrypt(b"We all live in a", b"YELLOW SUBMARINE").unwrap(),
                b"YELLOW SUBMARINE",
                true
            )
            .unwrap(),
            b"We all live in a"
        );
    }
}
