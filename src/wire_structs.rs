//! Plain byte-array structs that cross the network boundary.
//!
//! These types carry no serialization logic intentionally — add `serde`
//! derives or a manual codec before sending over a real transport.

use crate::{NH, NM, NN};

/// **Client → Server**, registration step 1.
///
/// Contains the client's OPRF-blinded password element.
/// Produced by [`client::registration_start`].
pub struct RegistrationRequest {
    pub blinded_element: [u8; 32],
}

/// **Server → Client**, registration step 2.
///
/// Contains the server's OPRF evaluation of the blinded element
/// and the server's static public key.
/// Produced by [`OpaqueSession::registration_start`].
pub struct RegistrationResponse {
    pub evaluated_element: [u8; 32],
    pub server_public_key: [u8; 32],
}

/// **Client → Server**, registration step 3.
///
/// Stored permanently in the server's database keyed by `credential_identifier`.
/// Contains everything the server needs to authenticate the client in future
/// logins, but reveals nothing about the password.
/// Produced by [`client::registration_finish`].
pub struct RegistrationRecord {
    pub client_public_key: [u8; 32],
    pub masking_key: [u8; NH],
    pub envelope_nonce: [u8; NN],
    pub envelope_auth_tag: [u8; NM],
}

/// **Client → Server**, login step 1.
///
/// Contains the blinded password element and the client's ephemeral AKE key.
/// Produced by [`client::login_start`].
pub struct Ke1 {
    pub blinded_element: [u8; 32],
    pub client_nonce: [u8; NN],
    pub client_ephemeral_pk: [u8; 32],
}

/// **Server → Client**, login step 2.
///
/// Contains the OPRF evaluation, the credential envelope, the server's
/// ephemeral AKE key, and the server's MAC over the handshake transcript.
/// Produced by [`OpaqueSession::login_start`].
pub struct Ke2 {
    pub evaluated_element: [u8; 32],
    pub envelope_nonce: [u8; NN],
    pub envelope_auth_tag: [u8; NM],
    pub server_public_key: [u8; 32], // server static pk, included in CredentialResponse
    pub server_nonce: [u8; NN],
    pub server_ephemeral_pk: [u8; 32],
    pub server_mac: [u8; NM],
}

/// **Client → Server**, login step 3.
///
/// Contains the client's MAC over the handshake transcript, proving knowledge
/// of the password and binding the session.
/// Produced by [`client::login_finish`].
pub struct Ke3 {
    pub client_mac: [u8; NM],
}
