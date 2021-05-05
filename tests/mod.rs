#![deny(clippy::correctness)]
#![warn(clippy::style)]
#![warn(clippy::complexity)]
#![warn(clippy::perf)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(clippy::cargo)]
#![allow(clippy::use_self)] // Not sure about this :/
#![allow(clippy::unreadable_literal)] // I don't like it on hex magic constants
#![allow(clippy::cast_precision_loss)] // I like it, but there are too many which renders it pointless
#![allow(clippy::cast_possible_truncation)] // I like it, but there are too many which renders it pointless
#![allow(clippy::needless_range_loop)] // Too many false positives, not very smart
#![allow(clippy::doc_markdown)] // Too many false positives, not very smart
#![allow(clippy::module_name_repetitions)] // Anti-pattern IMHO

mod set1;
mod set2;
mod set3;
mod set4;
mod set5;
mod set6;

use num_bigint::BigUint;
use num_traits::Num;
use once_cell::sync::Lazy;
use rand::{distributions, Rng};
use rustopals::rsa::{generate_rsa_keypair_from_primes, RSAPrivateKey, RSAPublicKey, E};

// Some 1024-bit RSA keypairs to avoid prime generation.
static RSA_KEYPAIR_0: Lazy<(RSAPublicKey, RSAPrivateKey)> = Lazy::new(|| {
    let p = BigUint::from_str_radix("c2daf71206b801d0d0805d3cad91c650dfe06f1d92ac44c72b41f2a362ff54670639cec218353e3a54fa68f9e1469800dee331e4b71b0a02284d42b9fad9cee9", 16).unwrap();
    let q = BigUint::from_str_radix("f4ea8ee535b3c80af47b902604742ad2db7af89d6e9e7bb75139839c50bf478f7fc5290d359acff41e23a680311c31afbd7aaec2814e3e73962a77036ebb608f", 16).unwrap();

    generate_rsa_keypair_from_primes(E.clone(), &p, &q).unwrap()
});

static RSA_KEYPAIR_1: Lazy<(RSAPublicKey, RSAPrivateKey)> = Lazy::new(|| {
    let p = BigUint::from_str_radix("994f1aa62ee83a1dc305057068ede154d13f28031570e7357825c54d9c830616ebc05e541ef6c3d595cf56769d9322d6bee65c5b1bf184fa7a51035ea2dac549", 16).unwrap();
    let q = BigUint::from_str_radix("b8ee0acba8cfbfc07f6ed0bbfaf572a0af5f72cc0a75ca4add92a5e0cb7a4b03410339fc24944982b5099908e72c253f2d55238693abaf7eeebacf0b9e69304f", 16).unwrap();

    generate_rsa_keypair_from_primes(E.clone(), &p, &q).unwrap()
});

static RSA_KEYPAIR_2: Lazy<(RSAPublicKey, RSAPrivateKey)> = Lazy::new(|| {
    let p = BigUint::from_str_radix("905793fc80550a17ce3a7c039c5aa739b3c1ebcb0fb2dabc09f9cedf0948d03bec7b7bffc4f037abecf998167b1d008519915f602134cde70a7be44809547ca3", 16).unwrap();
    let q = BigUint::from_str_radix("b853a2656a1a62fb6dce1ea2ecdbe45e184677643f7ee859196d3b311a0dcf7a95f8cff4cfa04466ee4a4489279f40384296b8ae2b07230856e0b8a2e1cc0c15", 16).unwrap();

    generate_rsa_keypair_from_primes(E.clone(), &p, &q).unwrap()
});

fn gen_random_bytes(length: usize) -> Vec<u8> {
    let rng = rand::thread_rng();

    rng.sample_iter(&distributions::Standard)
        .take(length)
        .collect::<Vec<_>>()
}

fn gen_random_bytes_between(min: usize, max: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let length = rng.gen_range(min..max);
    gen_random_bytes(length)
}
