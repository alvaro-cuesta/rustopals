//! [DSA](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm) signatures.

use std::marker::PhantomData;

use num_bigint::{BigInt, BigUint, RandBigInt};
use num_traits::{Num, Zero};
use once_cell::sync::Lazy;
use rand::thread_rng;

use crate::digest::{Digest, SHA1};
use crate::util::iter::ToHexable;
use crate::util::{inv_mod, math_mod};

/// A DSA instance with pre-chosen parameters. Used in Cryptopals challenges
/// as well as in tests.
pub static CHALLENGE_DSA: Lazy<DSA<SHA1>> = Lazy::new(|| {
    let p = BigUint::from_str_radix(
        "\
        800000000000000089e1855218a0e7dac38136ffafa72eda7\
        859f2171e25e65eac698c1702578b07dc2a1076da241c76c6\
        2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe\
        ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2\
        b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87\
        1a584471bb1",
        16,
    )
    .unwrap();

    let q = BigUint::from_str_radix("f4f47f05794b256174bba6e9b396a7707e563c5b", 16).unwrap();

    let g = BigUint::from_str_radix(
        "\
        5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119\
        458fef538b8fa4046c8db53039db620c094c9fa077ef389b5\
        322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047\
        0f5b64c36b625a097f1651fe775323556fe00b3608c887892\
        878480e99041be601a62166ca6894bdd41a7054ec89f756ba\
        9fc95302291",
        16,
    )
    .unwrap();

    DSA::new_from_params(p, q, g)
});

/// DSA instance with associated parameters.
pub struct DSA<D: Digest> {
    pub p: BigUint,
    pub q: BigUint,
    pub g: BigUint,
    digest: PhantomData<D>,
}

impl<D: Digest> DSA<D> {
    /// Generate a new DSA instance with randomly-generated parameters.
    ///
    /// # Panics
    ///
    /// Always (not implemented yet!)
    #[must_use]
    pub fn new() -> DSA<D> {
        unimplemented!()
    }

    /// Generate a new DSA instance specifying its parameters.
    #[must_use]
    pub fn new_from_params(p: BigUint, q: BigUint, g: BigUint) -> DSA<D> {
        DSA {
            p,
            q,
            g,
            digest: PhantomData,
        }
    }

    /// Generate a DSA keypair.
    #[must_use]
    pub fn gen_keypair(&self) -> (DSAPublicKey, DSAPrivateKey) {
        let one = BigUint::from(1_usize);

        let x = thread_rng().gen_biguint_range(&one, &(&self.q - &one));
        let y = self.g.modpow(&x, &self.p);

        (DSAPublicKey(y), DSAPrivateKey(x))
    }

    /// Implements a standard way to hash a message and turn it into an integer.
    fn hash_message(&self, message: &[u8]) -> BigUint {
        let hash_out = D::digest(message);
        let hash = hash_out.as_ref();
        let hash_int = BigUint::from_bytes_be(hash);
        #[allow(clippy::cast_possible_wrap)]
        let hash_excess_bits = (D::OUTPUT_LENGTH * 8) as isize - self.p.bits() as isize;

        if hash_excess_bits > 0 {
            hash_int >> hash_excess_bits
        } else {
            hash_int
        }
    }

    /// Signature implementation that also spies its chosen nonce (`k`) value.
    ///
    /// Used for tests.
    fn sign_spy(
        &self,
        DSAPrivateKey(x): &DSAPrivateKey,
        message: &[u8],
    ) -> (DSASignature, BigUint) {
        let one = BigUint::from(1_usize);

        let (k, r) = loop {
            let k = thread_rng().gen_biguint_range(&one, &(&self.q - &one));
            let r = self.g.modpow(&k, &self.p) % &self.q;

            if !r.is_zero() {
                break (k, r);
            }
        };

        let k_inv = inv_mod(k.clone(), &self.q).expect("No k^-1 found");

        let h_m = self.hash_message(message);

        let s = (k_inv * (h_m + x * &r)) % &self.q;

        (DSASignature { r, s }, k)
    }

    /// Sign a `message` with a `private_key`.
    #[must_use]
    pub fn sign(&self, private_key: &DSAPrivateKey, message: &[u8]) -> DSASignature {
        self.sign_spy(private_key, message).0
    }

    /// Verify a signature against `message`.
    #[must_use]
    pub fn verify(
        &self,
        DSAPublicKey(y): &DSAPublicKey,
        message: &[u8],
        DSASignature { r, s }: &DSASignature,
    ) -> bool {
        if r.is_zero() || s.is_zero() || r >= &self.q || s >= &self.q {
            return false;
        }

        let w = match inv_mod(s.clone(), &self.q) {
            Some(w) => w,
            None => return false,
        };

        let h_m = self.hash_message(message);

        let u_1 = (h_m * &w) % &self.q;
        let u_2 = (r * &w) % &self.q;

        let v = (self.g.modpow(&u_1, &self.p) * y.modpow(&u_2, &self.p)) % &self.p % &self.q;

        &v == r
    }

    /// Generate a private key given a signature, a hash message integer, and a
    /// (guessed) `k` value.
    ///
    /// By brute-forcing `k` you can recover the private key.
    #[must_use]
    pub fn crack_private_key_guess(
        &self,
        DSASignature { r, s }: &DSASignature,
        h_m: &BigUint,
        k: &BigUint,
    ) -> DSAPrivateKey {
        let r_inv = inv_mod(r.clone(), &self.q).expect("No r^-1 found.");

        DSAPrivateKey(math_mod(
            &((BigInt::from(s * k) - BigInt::from(h_m.clone())) * BigInt::from(r_inv)),
            &self.q,
        ))
    }

    /// Generate a private key a pair of signatures and hashes that are known
    /// to have been generated by a repeated nonce.
    #[must_use]
    pub fn crack_private_key_repeated_nonce(
        &self,
        pairs: [(&DSASignature, &BigUint); 2],
    ) -> Option<DSAPrivateKey> {
        let (DSASignature { r: r_1, s: s_1 }, h_m_1) = pairs[0];
        let (DSASignature { r: r_2, s: s_2 }, h_m_2) = pairs[1];

        if r_1 != r_2 {
            return None;
        }

        let m_sub = math_mod(
            &(BigInt::from(h_m_1.clone()) - BigInt::from(h_m_2.clone())),
            &self.q,
        );
        let s_sub = math_mod(
            &(BigInt::from(s_1.clone()) - BigInt::from(s_2.clone())),
            &self.q,
        );

        let s_sub_inv = inv_mod(s_sub, &self.q)?;

        let k = (m_sub * s_sub_inv) % &self.q;

        Some(self.crack_private_key_guess(pairs[0].0, h_m_1, &k))
    }
}

impl<D: Digest> Default for DSA<D> {
    fn default() -> DSA<D> {
        DSA::new()
    }
}

/// A DSA private key. Used for message signing.
#[derive(PartialEq, Eq, Debug)]
pub struct DSAPrivateKey(BigUint);

impl DSAPrivateKey {
    /// Get a private key fingerprint after converting it to a hex string.
    ///
    /// Used for tests only.
    #[must_use]
    pub fn fingerprint_after_hex<D: Digest>(&self) -> D::Output {
        let hex_bytes = self.0.to_bytes_be().into_hex();
        D::digest(hex_bytes.as_bytes())
    }
}

/// A DSA public key. Used fro signature verifying.
#[derive(PartialEq, Eq, Debug)]
pub struct DSAPublicKey(pub BigUint);

/// A DSA signature. Proves a message has been signed by the private key
/// corresponding to a known public key.
#[derive(PartialEq, Eq, Debug)]
pub struct DSASignature {
    pub r: BigUint,
    pub s: BigUint,
}

#[cfg(test)]
mod test {
    use super::{CHALLENGE_DSA, DSA};

    #[test]
    fn test_dsa_pregen() {
        const PLAINTEXT: &[u8] = b"THIS IS MY PLAINTEXT";

        let dsa: &DSA<_> = &CHALLENGE_DSA;
        let (public_key, private_key) = dsa.gen_keypair();

        let signature = dsa.sign(&private_key, PLAINTEXT);

        assert!(dsa.verify(&public_key, PLAINTEXT, &signature))
    }

    #[test]
    fn test_dsa_pregen_fail() {
        const PLAINTEXT: &[u8] = b"THIS IS MY PLAINTEXT";
        const BAD_PLAINTEXT: &[u8] = b"THIS IS AN UNRELATED PLAINTEXT";

        let dsa: &DSA<_> = &CHALLENGE_DSA;
        let (public_key, private_key) = dsa.gen_keypair();

        let signature = dsa.sign(&private_key, PLAINTEXT);

        assert!(!dsa.verify(&public_key, BAD_PLAINTEXT, &signature))
    }

    #[test]
    fn test_crack_private_key() {
        const PLAINTEXT: &[u8] = b"THIS IS MY PLAINTEXT";

        let dsa: &DSA<_> = &CHALLENGE_DSA;

        let (_public_key, private_key) = dsa.gen_keypair();

        let (signature, real_k) = dsa.sign_spy(&private_key, PLAINTEXT);

        let cracked_private_key =
            dsa.crack_private_key_guess(&signature, &dsa.hash_message(PLAINTEXT), &real_k);

        assert_eq!(private_key, cracked_private_key);
    }
}
