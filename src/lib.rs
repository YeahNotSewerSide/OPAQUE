//! OPAQUE asymmetric password-authenticated key exchange (aPAKE), RFC 9807.
//!
//! The server never sees the client's password — not during registration,
//! not during login. An attacker who steals the registration database cannot
//! run an offline dictionary attack without also compromising the server's
//! static private key.
//!
//! # Protocol flow
//!
//! ```text
//! REGISTRATION
//!   client::registration_start  →  RegistrationRequest
//!   server::OpaqueSession::registration_start  →  RegistrationResponse
//!   client::registration_finish  →  RegistrationRecord  (store in DB)
//!   server::OpaqueSession::registration_finish  →  stored RegistrationRecord
//!
//! LOGIN
//!   client::login_start  →  Ke1
//!   server::OpaqueSession::login_start  →  Ke2
//!   client::login_finish  →  (Ke3, SessionKey, export_key)
//!   server::OpaqueSession::login_finish  →  SessionKey
//! ```
//!
//! See the `examples/full_flow.rs` for a runnable end-to-end example.
//!
//! # Security notes
//!
//! - The `stretch` function in `utils` is currently the identity function.
//!   Replace it with Argon2id or scrypt before deploying.
//! - `Server::new` seeds are secret and must be persisted; losing them
//!   invalidates all existing registration records.

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

/// Errors that can be returned during an OPAQUE handshake.
///
/// All variants indicate a fatal failure — the session must be discarded.
#[derive(Debug)]
pub enum OpaqueError {
    /// The envelope auth tag did not match, meaning the password was wrong
    /// or the stored record was corrupted.
    EnvelopeRecoveryError,
    /// The server MAC in KE2 did not verify. The server is not authentic
    /// (possible MITM or wrong server identity).
    ServerAuthenticationError,
    /// The client MAC in KE3 did not verify. The client did not prove knowledge
    /// of the password (wrong password after a valid server response).
    ClientAuthenticationError,
    /// A session method was called out of order.
    /// The `&'static str` payload names the violated precondition.
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
