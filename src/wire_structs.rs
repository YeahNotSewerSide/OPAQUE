// =============================================================================
// Wire types — what crosses the network boundary
// =============================================================================

use crate::{NH, NM, NN};

// CLIENT → SERVER  (registration step 1)
pub struct RegistrationRequest {
    pub blinded_element: [u8; 32],
}

// SERVER → CLIENT  (registration step 2)
pub struct RegistrationResponse {
    pub evaluated_element: [u8; 32],
    pub server_public_key: [u8; 32],
}

// CLIENT → SERVER  (registration step 3, stored permanently)
pub struct RegistrationRecord {
    pub client_public_key: [u8; 32],
    pub masking_key: [u8; NH],
    pub envelope_nonce: [u8; NN],
    pub envelope_auth_tag: [u8; NM],
}

// CLIENT → SERVER  (login step 1)
pub struct Ke1 {
    pub blinded_element: [u8; 32],
    pub client_nonce: [u8; NN],
    pub client_ephemeral_pk: [u8; 32],
}

// SERVER → CLIENT  (login step 2)
pub struct Ke2 {
    pub evaluated_element: [u8; 32],
    pub envelope_nonce: [u8; NN],
    pub envelope_auth_tag: [u8; NM],
    pub server_public_key: [u8; 32], // server static pk, included in CredentialResponse
    pub server_nonce: [u8; NN],
    pub server_ephemeral_pk: [u8; 32],
    pub server_mac: [u8; NM],
}

// CLIENT → SERVER  (login step 3)
pub struct Ke3 {
    pub client_mac: [u8; NM],
}
