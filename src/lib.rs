//! Solutions for [Cryptopals Crypto Challenges](https://cryptopals.com/) implemented
//! in [Rust](https://www.rust-lang.org/).
//!
//! The final product should be a library of cryptographic primitives, implementing
//! as much crypto as possible (instead of using libraries). Code should be as
//! generic as possible. Usage of traits and generics instead of concrete types is
//! encouraged.
//!
//! The challenges will serve only as integration tests cases: the actual library
//! code is not organized around sets. If you want to review a specific challenge,
//! find it under the `/tests/` folder and explore the used functions.
//!
//! This is **not** a crypto library _(don't roll your own crypto!)_ but it should
//! serve as a real-world exercise.

#![feature(step_trait)]
#![feature(test)]
//
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

#[cfg(test)]
extern crate test;

pub mod block;
pub mod digest;
pub mod dsa;
pub mod key_exchange;
pub mod mac;
pub mod rand;
pub mod rsa;
pub mod stream;
pub mod util;
