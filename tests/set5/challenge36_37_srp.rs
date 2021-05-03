#![allow(clippy::many_single_char_names)]

use num_bigint::{BigUint, RandBigInt};
use once_cell::sync::Lazy;
use rand::thread_rng;
use rustopals::digest::{Digest, SHA256};
use rustopals::key_exchange::dh::NIST_MODULUS;
use rustopals::mac::hmac;

static G: Lazy<BigUint> = Lazy::new(|| BigUint::from(2_usize));
static K: Lazy<BigUint> = Lazy::new(|| BigUint::from(3_usize));

const EMAIL: &[u8] = b"will@example.com";
const PASSWORD: &[u8] = b"In west Philadelphia, born and raised";

struct Server {
    salt: Vec<u8>,
    v: BigUint,
    private_key: BigUint,
    public_key: BigUint,
}

impl Server {
    fn new() -> Server {
        let salt = crate::gen_random_bytes(32);

        let x_h = SHA256::new().chain(&salt).chain(PASSWORD).finalize();
        let x = BigUint::from_bytes_be(&x_h);

        let v = G.modpow(&x, &NIST_MODULUS);

        let private_key = thread_rng().gen_biguint_range(&BigUint::from(0_usize), &NIST_MODULUS);
        let public_key = (&K as &BigUint) * v.clone() + G.modpow(&private_key, &NIST_MODULUS);

        Server {
            salt,
            v,
            private_key,
            public_key,
        }
    }

    pub fn check_client_mac(
        &self,
        email: &[u8],
        client_public_key: &BigUint,
        their_mac: &<SHA256 as Digest>::Output,
    ) -> bool {
        if email != EMAIL {
            return false;
        }

        let u_h = SHA256::new()
            .chain(&client_public_key.to_bytes_be())
            .chain(&self.public_key.to_bytes_be())
            .finalize();
        let u = BigUint::from_bytes_be(&u_h);

        let s = (client_public_key.clone() * self.v.clone().modpow(&u, &NIST_MODULUS))
            .modpow(&self.private_key, &NIST_MODULUS);
        let k = SHA256::digest(&s.to_bytes_be());

        let my_mac = &hmac::<SHA256>(&k, &self.salt);

        their_mac == my_mac
    }

    fn get_salt(&self) -> &[u8] {
        &self.salt
    }

    const fn get_public(&self) -> &BigUint {
        &self.public_key
    }
}

struct Client {
    private_key: BigUint,
    public_key: BigUint,
}

impl Client {
    fn new() -> Client {
        let private_key = thread_rng().gen_biguint_range(&BigUint::from(0_usize), &NIST_MODULUS);
        let public_key = G.modpow(&private_key, &NIST_MODULUS);

        Client {
            private_key,
            public_key,
        }
    }

    fn get_data_for_server(
        self,
        password: &[u8],
        salt: &[u8],
        server_public_key: &BigUint,
    ) -> (BigUint, <SHA256 as Digest>::Output) {
        let u_h = SHA256::new()
            .chain(&self.public_key.to_bytes_be())
            .chain(&server_public_key.to_bytes_be())
            .finalize();
        let u = BigUint::from_bytes_be(&u_h);

        let x_h = SHA256::new().chain(salt).chain(password).finalize();
        let x = BigUint::from_bytes_be(&x_h);

        let s = (server_public_key.clone()
            - ((&K as &BigUint) * G.modpow(&x, &NIST_MODULUS)) % (&NIST_MODULUS as &BigUint))
            .modpow(&(self.private_key.clone() + u * x), &NIST_MODULUS);
        let k = SHA256::digest(&s.to_bytes_be());

        (self.public_key, hmac::<SHA256>(&k, salt))
    }
}

#[test]
fn test_normal_operation_ok() {
    let server = Server::new();
    let client = Client::new();

    let salt = server.get_salt();
    let server_public_key = server.get_public();

    let (client_public_key, client_mac) =
        client.get_data_for_server(PASSWORD, salt, server_public_key);

    assert!(server.check_client_mac(EMAIL, &client_public_key, &client_mac))
}

#[test]
fn test_normal_operation_fail() {
    let server = Server::new();
    let client = Client::new();

    let salt = server.get_salt();
    let server_public_key = server.get_public();

    let (client_public_key, client_mac) =
        client.get_data_for_server(b"NOT THE CORRECT PASSWORD", salt, server_public_key);

    assert!(!server.check_client_mac(EMAIL, &client_public_key, &client_mac))
}

#[test]
fn test_zero_key() {
    let server = Server::new();
    let zero = BigUint::from(0_usize);
    assert!(server.check_client_mac(
        EMAIL,
        &zero,
        &hmac::<SHA256>(&SHA256::digest(&zero.to_bytes_be()), server.get_salt())
    ))
}

#[test]
fn test_n_key() {
    let server = Server::new();
    let zero = BigUint::from(0_usize);

    assert!(server.check_client_mac(
        EMAIL,
        &NIST_MODULUS,
        &hmac::<SHA256>(&SHA256::digest(&zero.to_bytes_be()), server.get_salt())
    ));

    assert!(server.check_client_mac(
        EMAIL,
        &(BigUint::from(2_usize) * (&NIST_MODULUS as &BigUint)),
        &hmac::<SHA256>(&SHA256::digest(&zero.to_bytes_be()), server.get_salt())
    ));
}
