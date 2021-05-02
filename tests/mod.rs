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

use rand::{distributions, Rng};

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
