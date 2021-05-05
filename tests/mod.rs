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
    let p = BigUint::from_str_radix("1ae28a7709975a3584ccb3f6736a2e8cff920012d87195217dd4fe874978177217b294d6632fa4947f357141133aff91f20fa7d7d846cdf96a51348cc4a1f519", 16).unwrap();
    let q = BigUint::from_str_radix("a8939a961989a83296bc351f0108118ca00ce185166ec5347a1729c55e9a000156409049a45f9a9e35fa4c5c26405021d0ff173c2c4fd6b0dabd6e706d5a7f5", 16).unwrap();

    generate_rsa_keypair_from_primes(E.clone(), &p, &q).unwrap()
});

static RSA_KEYPAIR_1: Lazy<(RSAPublicKey, RSAPrivateKey)> = Lazy::new(|| {
    let p = BigUint::from_str_radix("efd9340b34a17a8a3d6a83ff9fa6c91b8f0be8f5353afc07e38e4c45eec9e13c80d57786d8b2737abf32f62c7bea51e853267df0f74846ba78a29c4f007e13f", 16).unwrap();
    let q = BigUint::from_str_radix("5de5597c67e6763c87da21d4285e2344d4526da6572fdb2ecd9b347103788dfe5283f5259360220c6d915adbacf1cb052107c2022dae194b9f172143c2087fa7", 16).unwrap();

    generate_rsa_keypair_from_primes(E.clone(), &p, &q).unwrap()
});

static RSA_KEYPAIR_2: Lazy<(RSAPublicKey, RSAPrivateKey)> = Lazy::new(|| {
    let p = BigUint::from_str_radix("e8e7ef9169a329cb5b11735b54368944862286584501694774065de9b48eaf9d3c616b698abcc1892cf2f220e78dbabd2a83eb4e740d768930eb9e2ea9477a81", 16).unwrap();
    let q = BigUint::from_str_radix("661cda8aca9de55bdb30240d8e5516cc94b82cfa9bd205240f9b050dc6e4d9730724e8ffe8b6ccf9c1428646f0c21c1857503ab117d92b1c7445688a3db5e9af", 16).unwrap();

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
