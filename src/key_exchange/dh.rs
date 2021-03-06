//! [Diffie-Hellman](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) key exchange.
//!
//! # Example
//!
//! ```
//! use rustopals::key_exchange::DHOffer;
//!
//! let alice_offer = DHOffer::new();
//! let bob_offer = DHOffer::new();
//!
//! let alice_session = alice_offer
//!     .clone()
//!     .establish(bob_offer.get_public())
//!     .unwrap();
//! let bob_session = bob_offer
//!     .establish(alice_offer.get_public())
//!     .unwrap();
//!
//! assert_eq!(
//!     alice_session.get_shared_secret(),
//!     bob_session.get_shared_secret(),
//! )
//! ```

use num_bigint::{BigUint, RandBigInt};
use num_traits::Zero;
use once_cell::sync::Lazy;
use rand::thread_rng;

use crate::digest::Digest;

/// NIST-recommended modulus for DH.
pub static NIST_MODULUS: Lazy<BigUint> = Lazy::new(|| {
    let bytes = base64::decode(
        "\
        ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
        e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
        3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
        6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
        24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
        c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
        bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
        fffffffffffff",
    )
    .unwrap();

    BigUint::from_bytes_be(&bytes)
});

/// NIST-recommended base for DH.
pub static NIST_BASE: Lazy<BigUint> = Lazy::new(|| BigUint::from(2_usize));

/// A Diffie-Hellman local offer.
#[derive(Clone, Debug)]
#[must_use]
pub struct DHOffer {
    modulus: BigUint,
    my_private: BigUint,
    my_public: BigUint,
}

impl DHOffer {
    /// Create a new Diffie-Hellman offer with a random private key.
    ///
    /// Uses the NIST-recommended parameters.
    pub fn new() -> DHOffer {
        DHOffer::new_custom(NIST_MODULUS.clone(), &NIST_BASE)
    }

    /// Create a new Diffie-Hellman offer specifying its private key.
    ///
    /// Uses the NIST-recommended parameters.
    #[must_use]
    pub fn new_from_private(my_private: BigUint) -> Option<DHOffer> {
        DHOffer::new_custom_from_private(NIST_MODULUS.clone(), &NIST_BASE, my_private)
    }

    /// Create a new Diffie-Hellman offer with a random private key,
    /// specifying custom DH parameters.
    pub fn new_custom(modulus: BigUint, base: &BigUint) -> DHOffer {
        let my_private = thread_rng().gen_biguint_range(&BigUint::zero(), &modulus);

        DHOffer::new_custom_from_private(modulus, base, my_private)
            .expect("Private key should have been valid")
    }

    /// Create a new Diffie-Hellman offer specifying its private key,
    /// specifying custom DH parameters.
    #[must_use]
    pub fn new_custom_from_private(
        modulus: BigUint,
        base: &BigUint,
        my_private: BigUint,
    ) -> Option<DHOffer> {
        /*
        HACK: I had to remove this for challenge 34 to be effective.
              Turns out validating untrusted input IS useful.

        if my_private >= modulus {
            return None;
        }
        */

        let my_public = base.modpow(&my_private, &modulus);

        Some(DHOffer {
            modulus,
            my_private,
            my_public,
        })
    }

    /// Get the offer's public key.
    #[must_use]
    pub const fn get_public(&self) -> &BigUint {
        &self.my_public
    }

    /// Establish a DH session by passing the other party's public key.
    #[must_use]
    pub fn establish(self, their_public: &BigUint) -> Option<DHSession> {
        /*
        HACK: I had to remove this for challenge 34 to be effective.
              Turns out validating untrusted input IS useful.

        if their_public >= &self.modulus {
            return None;
        }
        */

        let shared_secret = their_public.modpow(&self.my_private, &self.modulus);

        Some(DHSession {
            modulus: self.modulus,
            my_private: self.my_private,
            my_public: self.my_public,
            their_public: their_public.clone(),
            shared_secret,
        })
    }
}

impl Default for DHOffer {
    fn default() -> DHOffer {
        DHOffer::new()
    }
}

/// A Diffie-Hellman already-established session.
#[derive(Clone, Debug)]
#[must_use]
pub struct DHSession {
    modulus: BigUint,
    my_private: BigUint,
    my_public: BigUint,
    their_public: BigUint,
    shared_secret: BigUint,
}

impl DHSession {
    /// Get the established shared secret.
    ///
    /// Once a session is established by both parties (after exchanging their
    /// public keys) this value should be the same in both sessions.
    #[must_use]
    pub const fn get_shared_secret(&self) -> &BigUint {
        &self.shared_secret
    }

    /// Get my public key.
    #[must_use]
    pub const fn get_public(&self) -> &BigUint {
        &self.my_public
    }

    /// Get the other party's public key.
    #[must_use]
    pub const fn get_their_public(&self) -> &BigUint {
        &self.their_public
    }

    /// Clone this session into an unestablish DH offer.
    ///
    /// Useful if you want to re-establish the session.
    pub fn clone_to_offer(&self) -> DHOffer {
        DHOffer {
            modulus: self.modulus.clone(),
            my_private: self.my_private.clone(),
            my_public: self.my_public.clone(),
        }
    }

    /// Establish some key material from the shared secret using `D` as a digest.
    #[must_use]
    pub fn to_key_material<D: Digest>(&self) -> Vec<u8> {
        let bytes = self.shared_secret.to_bytes_be();
        D::digest(&bytes).as_ref().to_vec()
    }
}
