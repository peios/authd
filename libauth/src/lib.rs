//! Public authentication client C ABI. See include/peios/auth.h for the contract.
mod connection;
mod engine;

mod api;

mod results;

#[cfg(test)]
mod tests;
