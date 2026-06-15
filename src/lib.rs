use hmac::Hmac;
use sha2::Sha512;

pub mod client;
pub mod server;
mod utils;
pub mod wire_structs;

pub type HmacSha512 = Hmac<Sha512>;

pub const NN: usize = 32;
pub const NH: usize = 64;
pub const NM: usize = 64;
pub const NSEED: usize = 32;

#[derive(Debug)]
pub enum OpaqueError {
    EnvelopeRecoveryError,
    ServerAuthenticationError,
    ClientAuthenticationError,
    InvalidState(&'static str),
}

impl std::fmt::Display for OpaqueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EnvelopeRecoveryError => write!(f, "envelope auth tag mismatch"),
            Self::ServerAuthenticationError => write!(f, "server MAC verification failed"),
            Self::ClientAuthenticationError => write!(f, "client MAC verification failed"),
            Self::InvalidState(msg) => write!(f, "invalid state: {msg}"),
        }
    }
}
