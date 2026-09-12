#![forbid(unsafe_code)]

pub mod clock;
pub mod config;
pub mod domain;
pub mod enrichment;
pub mod http;
pub mod providers;
mod serialization;
pub mod server;
pub mod storage;

#[cfg(test)]
#[path = "../tests/application/mod.rs"]
mod tests;
