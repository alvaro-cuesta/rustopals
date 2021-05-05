//! [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) public-key cryptosystem.
//!
//! Enables asymmetric encryption and signatures.

mod primes;
mod util;

use num_bigint::{BigInt, BigUint};
use once_cell::sync::Lazy;
use util::{egcd, inv_mod};

use self::primes::gen_rsa_prime;

/// A not-very-safe default exponent (`3`).
///
/// It's not inherently insecure, but it's faster than the more secure `65537`.
pub static E: Lazy<BigUint> = Lazy::new(|| BigUint::from(3_usize));

/// An RSA public key.
///
/// Allows encrypting a message (that can be decrypted with its corresponding
/// private key) or veryfing a signature (that was generated with its
/// corresponding private key).
#[derive(Debug, PartialEq, Eq)]
pub struct RSAPublicKey {
    e: BigUint,
    n: BigUint,
}

impl RSAPublicKey {
    /// Process a message with [textbook RSA](https://crypto.stackexchange.com/questions/1448/definition-of-textbook-rsa).
    #[must_use]
    pub fn textbook_process(&self, message: &BigUint) -> Option<BigUint> {
        if message > &self.n {
            return None;
        }

        Some(message.modpow(&self.e, &self.n))
    }
}

/// An RSA private key.
///
/// Allows decrypting a message (that was encrypted with its corresponding
/// public key) or generating a signature (to be validated with its
/// corresponding public key).
#[derive(Debug, PartialEq, Eq)]
pub struct RSAPrivateKey {
    d: BigUint,
    n: BigUint,
}

impl RSAPrivateKey {
    /// Process a message with [textbook RSA](https://crypto.stackexchange.com/questions/1448/definition-of-textbook-rsa).
    #[must_use]
    pub fn textbook_process(&self, message: &BigUint) -> Option<BigUint> {
        if message > &self.n {
            return None;
        }

        Some(message.modpow(&self.d, &self.n))
    }
}

/// Randomly generate an RSA keypair with an specific exponent `e`.
#[must_use]
pub fn generate_rsa_keypair(bits: u32, e: &BigUint) -> (RSAPublicKey, RSAPrivateKey) {
    loop {
        let p = gen_rsa_prime(bits / 2, e);
        let q = gen_rsa_prime(bits / 2, e);

        match generate_rsa_keypair_from_primes(e.clone(), &p, &q) {
            Some(x) => return x,
            None => continue,
        }
    }
}

/// Generate an RSA keypair with an specific exponent `e` and primes `p` and `q`.
///
/// Returns `None` if a keypair cannot be generated with the specified parameters.
#[must_use]
#[allow(clippy::many_single_char_names)]
pub fn generate_rsa_keypair_from_primes(
    e: BigUint,
    p: &BigUint,
    q: &BigUint,
) -> Option<(RSAPublicKey, RSAPrivateKey)> {
    let p_1 = p - BigUint::from(1_usize);
    let q_1 = q - BigUint::from(1_usize);

    // We use Carmichael's instead of Euler's totient
    // Should work the same and be more compatible, and smaller
    let (gcd_p_1_q_1, _, _) = egcd(BigInt::from(p_1.clone()), BigInt::from(q_1.clone()));
    let totient = p_1 * q_1
        / gcd_p_1_q_1
            .to_biguint()
            .expect("GCD shouldn't have been negative");

    let n = p * q;
    let d = inv_mod(e.clone(), &totient)?;

    Some((RSAPublicKey { e, n: n.clone() }, RSAPrivateKey { d, n }))
}

/// Perform an E=3 Broadcast attack given three pairs of `(public_key, ciphertext)`.
///
/// Each ciphertext must have been ecnrypted by its corresponding public key, and
/// all of them must be the encryption of the same plaintext.
///
/// Returns the common `plaintext`.
#[must_use]
#[allow(clippy::missing_panics_doc)]
pub fn e_3_broadcast_attack(input: [(&RSAPublicKey, &BigUint); 3]) -> BigUint {
    let (RSAPublicKey { n: n_0, .. }, c_0) = input[0];
    let (RSAPublicKey { n: n_1, .. }, c_1) = input[1];
    let (RSAPublicKey { n: n_2, .. }, c_2) = input[2];

    let m_s_0 = n_1 * n_2;
    let m_s_1 = n_0 * n_2;
    let m_s_2 = n_0 * n_1;

    let n_0_1_2 = n_0 * n_1 * n_2;

    let crt_result = ((c_0 * &m_s_0 * inv_mod(m_s_0, n_0).unwrap())
        + (c_1 * &m_s_1 * inv_mod(m_s_1, n_1).unwrap())
        + (c_2 * &m_s_2 * inv_mod(m_s_2, n_2).unwrap()))
        % &n_0_1_2;

    crt_result.cbrt()
}

/// Malleates a ciphertext to make it look different to an `oracle`, and later
/// recovers the original plaintext for the oracle's response.
///
/// This works because RSA is homomorphic under multiplication.
pub fn unpadded_message_recovery<O>(
    public_key: &RSAPublicKey,
    s: &BigUint,
    ciphertext: &BigUint,
    oracle: O,
) -> BigUint
where
    O: FnOnce(&BigUint) -> BigUint,
{
    let malleated_ciphertext =
        (s.modpow(&public_key.e, &public_key.n) * ciphertext) % &public_key.n;

    let almost_recovered_plaintext = oracle(&malleated_ciphertext);

    (almost_recovered_plaintext * inv_mod(s.clone(), &public_key.n).unwrap()) % &public_key.n
}

#[cfg(test)]
mod test {
    use num_bigint::{BigUint, RandBigInt};
    use rand::thread_rng;

    use super::{generate_rsa_keypair, generate_rsa_keypair_from_primes, E};

    #[test]
    fn test_rsa_bad_keygen() {
        let keypair = generate_rsa_keypair_from_primes(
            E.clone(),
            &BigUint::from(7_usize),
            &BigUint::from(11_usize),
        );

        assert_eq!(keypair, None);
    }

    #[test]
    fn test_rsa_full() {
        let (public_key, private_key) = generate_rsa_keypair_from_primes(
            E.clone(),
            &BigUint::from(11_usize),
            &BigUint::from(23_usize),
        )
        .unwrap();

        // Random plaintext
        {
            let plaintext = thread_rng().gen_biguint_range(&BigUint::from(0_usize), &public_key.n);
            let ciphertext = public_key.textbook_process(&plaintext).unwrap();

            assert_eq!(private_key.textbook_process(&ciphertext), Some(plaintext));
        }

        // n-1 plaintext
        {
            let plaintext = &public_key.n - &BigUint::from(1_usize);
            let ciphertext = public_key.textbook_process(&plaintext).unwrap();

            assert_eq!(private_key.textbook_process(&ciphertext), Some(plaintext));
        }
    }

    #[test]
    fn test_rsa_full_big_primes() {
        let (public_key, private_key) = generate_rsa_keypair(1024, &E);

        // Random plaintext
        {
            let plaintext = thread_rng().gen_biguint_range(&BigUint::from(0_usize), &public_key.n);
            let ciphertext = public_key.textbook_process(&plaintext).unwrap();

            assert_eq!(private_key.textbook_process(&ciphertext), Some(plaintext));
        }

        // n-1 plaintext
        {
            let plaintext = &public_key.n - &BigUint::from(1_usize);
            let ciphertext = public_key.textbook_process(&plaintext).unwrap();

            assert_eq!(private_key.textbook_process(&ciphertext), Some(plaintext));
        }
    }
}
